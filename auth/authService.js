/* eslint-disable no-prototype-builtins */
const jwt = require('jsonwebtoken')
const rp = require('request-promise')
const { v4: uuidv4 } = require('uuid')
const Sequelize = require('sequelize')
const Hashids = require('hashids/cjs')

const hashids = new Hashids('Bookis', 8)

const defaults = require('../../config/defaults.json')
const { mapper } = require('../../utils')
const {
	ValidationError, ServerError, AuthError, ConflictError
} = require('../../utils').errors

const objectConstructor = ({}).constructor

function parseError (errorMessage) {
	try {
		return JSON.parse(errorMessage)
	} catch (err) {
		this.logger.warn('Auth service parse error', { additionalInfo: err })
		return null
	}
}

module.exports = class AuthService {
	constructor ({
		logger, pgSqlDbContext, env, userService, s3Service
	}) {
		this.logger = logger
		this.db = pgSqlDbContext
		this.env = env
		this.userService = userService
		this.s3Service = s3Service
	}

	refreshToken (token, refreshToken) {
		if (!token || !refreshToken) {
			throw new ValidationError('Token is empty!')
		}
		const { email } = jwt.decode(token)
		return this.userService.getByEmail(email, true).then(user => rp({
			method: 'POST',
			uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/refresh-token`,
			resolveWithFullResponse: true,
			body: JSON.stringify({
				refreshToken,
				email: user.email,
				accountId: user.id
			}),
			headers: {
				'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
				country: this.env.getEnvProp('COUNTRY')
			}
		})
			.then((authResponse) => {
				const parsedBody = JSON.parse(authResponse.body)
				const accessToken = parsedBody.access_token
				const parsedNewToken = jwt.decode(accessToken)
				return this.userService.getByEmail(parsedNewToken.email, true)
					.then(usr => mapper.models.getUser(usr))
					.then(account => ({
						token: parsedBody.access_token,
						refresh_token: parsedBody.refresh_token,
						expire_time: parsedBody.expire_time,
						user: account
					}))
					.catch((e) => {
						this.logger.error('Error: ', { additionalInfo: e })
						throw new ServerError(e.stack || e.message)
					})
			})
			.catch((err) => {
				this.logger.error('Failed to refresh token!', { additionalInfo: err })
				throw new ServerError(err.stack || err.message)
			}))
			.catch((err) => {
				this.logger.error('Something went wrong', { additionalInfo: err })
				throw new ServerError(err.stack || err.message)
			})
	}

	async uploadSocialUserToCognito (user) {
		const pass = `0${hashids.encode(user.id)}`
		return rp({
			method: 'POST',
			uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/sign-up-confirmed`,
			resolveWithFullResponse: true,
			headers: {
				'Content-Type': 'application/json',
				'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
				country: this.env.getEnvProp('COUNTRY')
			},
			json: true,
			body: {
				email: user.email,
				password: pass
			}
		}).then(() => this.db.UserSocial.create({
			UserId: user.id, provider: user.provider, userRole: user.role, cognitoVerified: false
		})) // this.db.User.update({ active: true, role: 'oldUser' }, { where: { id: user.id } })
			.catch((err) => {
				console.log(err && err.message)
				if (err.message.includes('already exists')) {
					console.log('Create UserSocial for ', user.email)
					return this.db.UserSocial.create({
						UserId: user.id, provider: user.provider, userRole: user.role, cognitoVerified: false
					})
				}
				return null
			})
	}

	async reactivateUser (user) {
		return this.db.Sale.update({ status: 'available' }, { where: { status: 'userDeactivated', SellerId: user.id } })
	}

	async resetPassword (email) {
		if (!email) {
			throw new ValidationError('Email is empty!')
		}
		const user = await this.userService.getByEmail(email, true)
		if (!user) {
			throw new ValidationError('User not found!')
		}
		if (!user.active) {
			throw new ValidationError('User not activated!')
		}
		let cognitoMethod = 'reset-password'
		if (user.role === 'oldUser') {
			cognitoMethod = 'reset-password-confirmed'
		}
		return rp({
			method: 'POST',
			uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/${cognitoMethod}`,
			resolveWithFullResponse: true,
			body: JSON.stringify({
				email: user.email,
				password: uuidv4().substring(0, 8)
			}),
			headers: {
				'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
				country: this.env.getEnvProp('COUNTRY')
			}
		})
			.then(response => response)
			.catch((err) => {
				console.log(err.stack || err.message)
				if (err.error) {
					const parsedError = err.error.constructor === objectConstructor ? err.error : parseError(err.error)
					let errorMessage = err.message
					if (parsedError && parsedError.reason &&
						((parsedError.reason.cause && parsedError.reason.cause.message) || parsedError.reason.message)
					) {
						errorMessage = parsedError.reason.cause ? parsedError.reason.cause.message : parsedError.reason.message
					}
					throw new AuthError(errorMessage)
				}
				throw new ServerError(err.stack || err.message)
			})
	}

	async confirmResetPassword (query) {
		if (!query) {
			throw new ValidationError('Request body is empty!')
		}
		const { email, code, password } = query
		if (!email || !code || !password) {
			throw new ValidationError('Bad confirm password request')
		}
		const user = await this.userService.getByEmail(email, true)
		if (!user) {
			throw new ValidationError('User not found!')
		}
		return rp({
			method: 'POST',
			uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/confirm-reset-password`,
			resolveWithFullResponse: true,
			body: JSON.stringify({
				email,
				code,
				password
			}),
			headers: {
				'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
				country: this.env.getEnvProp('COUNTRY')
			}
		})
			.then(response => response)
			.catch((err) => {
				console.log(err.stack || err.message)
				if (err.error) {
					const parsedError = err.error.constructor === objectConstructor ? err.error : parseError(err.error)
					let errorMessage = err.message
					if (parsedError && parsedError.reason &&
						((parsedError.reason.cause && parsedError.reason.cause.message) || parsedError.reason.message)
					) {
						errorMessage = parsedError.reason.cause ? parsedError.reason.cause.message : parsedError.reason.message
					}
					throw new AuthError(errorMessage)
				}
				throw new ServerError(err.stack || err.message)
			})
	}

	async resendCode (email) {
		if (!email) {
			throw new ValidationError('Email is empty!')
		}
		const user = await this.userService.getByEmail(email, true)
		if (!user) {
			throw new ValidationError('User not found!')
		}
		return rp({
			method: 'POST',
			uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/resend-code`,
			resolveWithFullResponse: true,
			body: JSON.stringify({
				email: user.email
			}),
			headers: {
				'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
				country: this.env.getEnvProp('COUNTRY')
			}
		}).then((resp) => {
			if (resp && resp.statusCode === 200) {
				return {
					message: 'New confirmation code was successfully sent'
				}
			}
			throw new ServerError(resp.body)
		}).catch((err) => {
			console.log(err.stack || err.message)
			if (err.error) {
				const parsedError = err.error.constructor === objectConstructor ? err.error : parseError(err.error)
				let errorMessage = err.message
				if (parsedError && parsedError.reason &&
					((parsedError.reason.cause && parsedError.reason.cause.message) || parsedError.reason.message)
				) {
					errorMessage = parsedError.reason.cause ? parsedError.reason.cause.message : parsedError.reason.message
				}
				throw new AuthError(errorMessage)
			}
			throw new ServerError(err.stack || err.message)
		})
	}

	localAuthenticate (userId, email, password) {
		if (password === process.env.LOCAL_PASS) {
			return this.userService.getByEmail(email, true)
				.then((user) => {
					const token = jwt.sign({ accountId: user.id, role: user.role }, process.env.ENCODE_SECRET_KEY, { expiresIn: 1000 * 60 * 60 * 24 })
					const now = Date.now()
					const expireTime = new Date(now + 1000 * 60 * 60 * 24)
					return {
						token,
						refresh_token: '',
						expire_time: expireTime,
						user
					}
				})
				.catch((e) => {
					this.logger.error('Authenticate error with local pass: ', { additionalInfo: e })
					return e
				})
		}
		return rp({
			method: 'POST',
			uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/auth`,
			resolveWithFullResponse: true,
			body: JSON.stringify({
				accountId: userId,
				login: email,
				password
			}),
			headers: {
				'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
				country: this.env.getEnvProp('COUNTRY')
			}
		}).then((authResponse) => {
			const parsedBody = JSON.parse(authResponse.body)
			const accessToken = parsedBody.access_token
			const parsedToken = jwt.decode(accessToken)
			return this.userService.getByEmail(parsedToken.email, true)
				.then(usr => mapper.models.getUser(usr, true))
				.then(user => ({
					token: accessToken,
					refresh_token: parsedBody.refresh_token,
					expire_time: parsedBody.expire_time,
					user
				}))
				.catch((e) => {
					this.logger.error('User error: ', { additionalInfo: e })
					return e
				})
		}).catch((err) => {
			this.logger.error('Authenticate error', { additionalInfo: err })
			if (err.error) {
				const parsedError = err.error.constructor === objectConstructor ? err.error : parseError(err.error)
				let errorMessage = err.message
				if (parsedError && parsedError.reason &&
					((parsedError.reason.cause && parsedError.reason.cause.message) || parsedError.reason.message)
				) {
					errorMessage = parsedError.reason.cause ? parsedError.reason.cause.message : parsedError.reason.message
				}
				throw new AuthError(errorMessage)
			}
			throw new ServerError(err.stack || err.message)
		})
	}

	async signUp (userStub, countryCode) {
		if (!userStub || !userStub.email) {
			throw new ValidationError('Bad create user request')
		}
		// eslint-disable-next-line no-param-reassign
		userStub.email = userStub.email.toLowerCase()
		const userPass = userStub.password
		const country = await this.db.Country.findOne({
			where: {
				code: process.env.COUNTRY
			}
		})
		const user = await this.db.User.findOne({
			where: {
				email: userStub.email
			}
		})
		if (!user && userStub.role === 'guest') {
			return this.db.User.create({
				firstName: userStub.firstName || 'Anonymous',
				lastName: userStub.lastName || userStub.firstName || 'Anonymous',
				email: userStub.email,
				phone: userStub.phone || '',
				active: true,
				provider: 'local',
				CountryId: (country && country.id) || null,
				role: userStub.role,
				currency: userStub.currency || defaults[countryCode.toLowerCase()].currency
			}).then(usr => mapper.models.getUser(usr, true))
		}
		return rp({
			method: 'POST',
			uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/sign-up`,
			resolveWithFullResponse: true,
			headers: {
				'Content-Type': 'application/json',
				'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
				country: this.env.getEnvProp('COUNTRY')
			},
			json: true,
			body: {
				email: userStub.email,
				password: userPass
			}
		}).then((result) => {
			if (result.statusCode === 200) {
				if (user && user.role === 'guest') {
					return this.db.User.update({
						active: false,
						role: 'user',
						provider: 'local',
						emailVerified: false
					}, { where: { id: user.id }	})
						.then(() => this.db.User.findByPk(user.id).then(usr => mapper.models.getUser(usr, true)))
				}
				return this.db.User.create({
					firstName: userStub.firstName || 'Anonymous',
					lastName: userStub.lastName || userStub.firstName || 'Anonymous',
					email: userStub.email,
					phone: userStub.phone || '',
					active: false,
					provider: 'local',
					CountryId: (country && country.id) || null,
					role: userStub.role || 'user',
					currency: userStub.currency || defaults[countryCode.toLowerCase()].currency
				})
					.then(usr => mapper.models.getUser(usr, true))
			}
			return null
		}).catch((err) => {
			this.logger.error('Sign up error', { additionalInfo: err })
			if (err.error) {
				const parsedError = err.error.constructor === objectConstructor ? err.error : parseError(err.error)
				let errorMessage = err.message
				if (parsedError && parsedError.reason &&
					((parsedError.reason.cause && parsedError.reason.cause.message) || parsedError.reason.message)
				) {
					errorMessage = parsedError.reason.cause ? parsedError.reason.cause.message : parsedError.reason.message
				}
				throw new AuthError(errorMessage)
			}
			throw new ServerError(err.message || err.stack)
		})
	}

	async confirmSignUp (userId, email, code) {
		return rp({
			method: 'POST',
			uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/confirm-sign-up`,
			resolveWithFullResponse: true,
			headers: {
				'Content-Type': 'application/json',
				'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
				country: this.env.getEnvProp('COUNTRY')
			},
			json: true,
			body: {
				email,
				code
			}
		}).then((result) => {
			if (result.statusCode === 200) {
				return this.db.User.update({ active: true, emailVerified: true }, { where: { id: userId } })
					.then((usr) => {
						if (!usr || !usr[1] || !usr[1][0]) {
							return this.db.User.findOne({
								where: {
									id: userId
								}
							}).then(user => mapper.models.getUser(user))
						}
						return mapper.models.getUser(usr[1][0])
					})
			}
			return null
		}).catch((err) => {
			console.log(err.message || err.stack)
			if (err.error) {
				const parsedError = err.error.constructor === objectConstructor ? err.error : parseError(err.error)
				let errorMessage = err.message
				if (parsedError && parsedError.reason &&
					((parsedError.reason.cause && parsedError.reason.cause.message) || parsedError.reason.message)
				) {
					errorMessage = parsedError.reason.cause ? parsedError.reason.cause.message : parsedError.reason.message
				}
				throw new AuthError(errorMessage)
			}
			throw new ServerError(err.message || err.stack)
		})
	}

	async changePassword (token, newPassword, oldPassword) {
		if (!token || !newPassword || !oldPassword) {
			throw new ValidationError('Bad request')
		}
		const bodyToken = token.replace('Bearer ', '')
		const { accessToken } = jwt.decode(bodyToken)
		if (newPassword.length < 8) {
			throw new ValidationError('Password did not conform with policy: length less than 8 symbols')
		}
		return rp({
			method: 'POST',
			uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/change-password`,
			resolveWithFullResponse: true,
			headers: {
				'Content-Type': 'application/json',
				'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
				country: this.env.getEnvProp('COUNTRY')
			},
			json: true,
			body: {
				accessToken,
				previousPassword: oldPassword,
				proposedPassword: newPassword
			}
		}).then((result) => {
			if (result.statusCode === 200) {
				return true
			}
			return null
		}).catch((err) => {
			this.logger.error('Change pass error', { additionalInfo: err })
			if (err.error) {
				const parsedError = err.error.constructor === objectConstructor ? err.error : parseError(err.error)
				let errorMessage = err.message
				if (parsedError && parsedError.reason &&
					((parsedError.reason.cause && parsedError.reason.cause.message) || parsedError.reason.message)
				) {
					errorMessage = parsedError.reason.cause ? parsedError.reason.cause.message : parsedError.reason.message
				}
				throw new AuthError(errorMessage)
			}
			throw new ServerError(err.message || err.stack)
		})
	}

	async googleAuthenticate (token, countryCode) {
		return rp({
			method: 'POST',
			uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/google-login`,
			resolveWithFullResponse: true,
			body: JSON.stringify({
				token
			}),
			headers: {
				'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
				country: this.env.getEnvProp('COUNTRY')
			}
		}).then(async (authResponse) => {
			const country = await this.db.Country.findOne({
				where: {
					code: process.env.COUNTRY
				}
			})
			const parsedBody = JSON.parse(authResponse.body)
			const accessToken = parsedBody.access_token
			const parsedToken = jwt.decode(accessToken)
			let user
			if (parsedToken.id) {
				user = await this.db.User.findOne({
					where: {
						googleId: parsedToken.id
					},
					attributes: ['id', 'guid', 'firstName', 'imageUrl', 'createdAt', 'updatedAt', 'acceptedTerms', 'email', 'active', 'role', 'provider', 'emailVerified', 'lastName', 'googleId', 'googleDisplayName', 'AuthorId'],
					include: [
						{
							model: this.db.UserSocial,
							required: false
						}
					]
				})
			}
			if (!user) {
				user = await this.userService.getByEmail(parsedToken.email, true, false)
				if (user && parsedToken.id) {
					await this.db.User.update({ googleId: parsedToken.id, googleDisplayName: parsedToken.fullName }, { where: { id: user.id } })
				}
			}
			const newUser = !user
			if (newUser) {
				user = await this.db.User.create({
					googleId: parsedToken.id,
					googleDisplayName: parsedToken.fullName,
					firstName: parsedToken.firstName || 'Anonymous',
					lastName: parsedToken.lastName || parsedToken.firstName || 'Anonymous',
					email: parsedToken.email,
					phone: parsedToken.phone || '',
					active: true,
					emailVerified: true,
					provider: 'google',
					CountryId: (country && country.id) || null,
					currency: parsedToken.currency || defaults[countryCode.toLowerCase()].currency
				})
				try {
					await this.uploadSocialUserToCognito(user)
				} catch (err) {
					this.logger.error(err)
				}
			} else if (user.provider === 'google' && !user.UserSocial) {
				try {
					await this.uploadSocialUserToCognito(user)
				} catch (err) {
					this.logger.error(err)
				}
			}
			if (!user.imageUrl && parsedToken.avatar_url) {
				try {
					const userObj = user.toJSON()
					userObj.imageUrl = parsedToken.avatar_url
					user.imageUrl = await this.s3Service.attachS3Link(userObj, 'google')
					user = await user.save()
				} catch (err) {
					this.logger.warn(err)
				}
			}
			if (!newUser && !user.active) {
				return {
					error: 'User not active!',
					data: {
						email: user.email,
						token: accessToken,
						refresh_token: parsedBody.refresh_token,
						expire_time: parsedBody.expire_time
					},
					statusCode: 401
				}
			}
			user = mapper.models.getUser(user, true)
			return {
				token: accessToken,
				refresh_token: parsedBody.refresh_token,
				expire_time: parsedBody.expire_time,
				user,
				newUser
			}
		}).catch((err) => {
			this.logger.error('Google auth error', { additionalInfo: err })
			if (err.error) {
				const parsedError = err.error.constructor === objectConstructor ? err.error : parseError(err.error)
				let errorMessage = err.message
				if (parsedError && parsedError.reason &&
					((parsedError.reason.cause && parsedError.reason.cause.message) || parsedError.reason.message)
				) {
					errorMessage = parsedError.reason.cause ? parsedError.reason.cause.message : parsedError.reason.message
				}
				throw new AuthError(errorMessage)
			}
			throw new ServerError(err.stack || err.message)
		})
	}

	async facebookAuthenticate (token, countryCode) {
		return rp({
			method: 'POST',
			uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/facebook-login`,
			resolveWithFullResponse: true,
			body: JSON.stringify({
				token
			}),
			headers: {
				'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
				country: this.env.getEnvProp('COUNTRY')
			}
		}).then(async (authResponse) => {
			const country = await this.db.Country.findOne({
				where: {
					code: process.env.COUNTRY
				}
			})
			const parsedBody = JSON.parse(authResponse.body)
			const accessToken = parsedBody.access_token
			const parsedToken = jwt.decode(accessToken)
			let user
			const { Op } = Sequelize
			if (parsedToken.id) {
				user = await this.db.User.findOne({
					where: {
						[Op.or]: [
							{
								facebookId: parsedToken.id
							},
							{
								email: `${parsedToken.id}@facebook.com`
							}
						]
					},
					attributes: ['id', 'guid', 'firstName', 'imageUrl', 'createdAt', 'updatedAt', 'acceptedTerms', 'email', 'active', 'role', 'provider', 'emailVerified', 'lastName', 'facebookId', 'facebookEmail', 'facebookName', 'AuthorId'],
					include: [
						{
							model: this.db.UserSocial,
							required: false
						}
					]
				})
			}
			if (!user) {
				user = await this.userService.getByEmail(parsedToken.email, true, false)
				if (user && parsedToken.id) {
					await this.db.User.update({ facebookId: parsedToken.id, facebookName: parsedToken.facebookName }, { where: { id: user.id } })
				}
			}
			const newUser = !user
			if (newUser) {
				user = await this.db.User.create({
					facebookId: parsedToken.id,
					facebookName: parsedToken.facebookName,
					firstName: parsedToken.firstName || 'Anonymous',
					lastName: parsedToken.lastName || parsedToken.firstName || 'Anonymous',
					email: parsedToken.email,
					phone: parsedToken.phone || '',
					active: true,
					emailVerified: true,
					provider: 'facebook',
					CountryId: (country && country.id) || null,
					currency: parsedToken.currency || defaults[countryCode.toLowerCase()].currency
				})
				try {
					await this.uploadSocialUserToCognito(user)
				} catch (err) {
					this.logger.error(err)
				}
			} else if (user.provider === 'facebook' && !user.UserSocial && !user.email.includes(parsedToken.id)) {
				try {
					await this.uploadSocialUserToCognito(user)
				} catch (err) {
					this.logger.error(err)
				}
			}
			if (!user.imageUrl && parsedToken.avatar_url) {
				try {
					const userObj = user.toJSON()
					userObj.imageUrl = parsedToken.avatar_url
					user.imageUrl = await this.s3Service.attachS3Link(userObj, 'facebook')
					user = await user.save()
				} catch (err) {
					this.logger.warn(err)
				}
			}
			if (!newUser && !user.active) {
				return {
					error: 'User not active!',
					data: {
						email: user.email,
						token: accessToken,
						refresh_token: parsedBody.refresh_token,
						expire_time: parsedBody.expire_time
					},
					statusCode: 401
				}
			}
			user = mapper.models.getUser(user, true)
			return {
				token: accessToken,
				refresh_token: parsedBody.refresh_token,
				expire_time: parsedBody.expire_time,
				user,
				newUser
			}
		}).catch((err) => {
			console.log(err)
			this.logger.error('Facebook auth error', { additionalInfo: err })
			if (err.error) {
				const parsedError = err.error.constructor === objectConstructor ? err.error : parseError(err.error)
				let errorMessage = err.message
				if (parsedError && parsedError.reason &&
					((parsedError.reason.cause && parsedError.reason.cause.message) || parsedError.reason.message)
				) {
					errorMessage = parsedError.reason.cause ? parsedError.reason.cause.message : parsedError.reason.message
				}
				throw new AuthError(errorMessage)
			}
			throw new ServerError(err.stack || err.message)
		})
	}

	async appleAuthenticate (token, fullName, redirect = false, countryCode) {
		return rp({
			method: 'POST',
			uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/apple-login`,
			resolveWithFullResponse: true,
			body: JSON.stringify({
				token,
				fullName
			}),
			headers: {
				'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
				country: this.env.getEnvProp('COUNTRY')
			}
		}).then(async (authResponse) => {
			const country = await this.db.Country.findOne({
				where: {
					code: process.env.COUNTRY
				}
			})
			const parsedBody = JSON.parse(authResponse.body)
			const accessToken = parsedBody.access_token
			const parsedToken = jwt.decode(accessToken)
			let user = await this.userService.getByEmail(parsedToken.email, true, false)
			const newUser = !user
			if (!user) {
				user = await this.db.User.create({
					firstName: parsedToken.firstName || 'Anonymous',
					lastName: parsedToken.lastName || parsedToken.firstName || 'Anonymous',
					email: parsedToken.email,
					phone: parsedToken.phone || '',
					active: true,
					emailVerified: true,
					provider: 'apple',
					CountryId: (country && country.id) || null,
					currency: parsedToken.currency || defaults[countryCode.toLowerCase()].currency
				})
			}
			if (!user.imageUrl && parsedToken.avatar_url) {
				const userObj = user.toJSON()
				userObj.imageUrl = parsedToken.avatar_url
				user.imageUrl = await this.s3Service.attachS3Link(userObj, 'apple')
				user = await user.save()
			}
			if (!newUser && !user.active) {
				return {
					error: 'User not active!',
					data: {
						email: user.email,
						token: accessToken,
						refresh_token: parsedBody.refresh_token,
						expire_time: parsedBody.expire_time
					},
					statusCode: 401
				}
			}
			user = mapper.models.getUser(user, true)
			return {
				token: accessToken,
				refresh_token: parsedBody.refresh_token,
				expire_time: parsedBody.expire_time,
				user,
				newUser,
				redirect: redirect && `${process.env.BASE_URL}${process.env.COUNTRY.toLowerCase()}/auth/apple-redirect?token=${accessToken}`
			}
		}).catch((err) => {
			this.logger.error('Apple auth error', { additionalInfo: err })
			if (err.error) {
				const parsedError = err.error.constructor === objectConstructor ? err.error : parseError(err.error)
				let errorMessage = err.message
				if (parsedError && parsedError.reason &&
					((parsedError.reason.cause && parsedError.reason.cause.message) || parsedError.reason.message)
				) {
					errorMessage = parsedError.reason.cause ? parsedError.reason.cause.message : parsedError.reason.message
				}
				throw new AuthError(errorMessage)
			}
			throw new ServerError(err.stack || err.message)
		})
	}

	async reactivateSocial (email) {
		console.log('reactivate user: ', email)
		const user = await this.userService.getByEmail(email, true, false)
		if (user.provider !== 'local' && !user.active) {
			await this.reactivateUser(user)
			user.active = true
			await user.save()
		} else {
			throw new ValidationError('Can\'t reactive user!')
		}
		return {
			user: mapper.models.getUser(user, true)
		}
	}

	async signUpGuest (guest) {
		const { email, password } = guest
		if (!email || !password) {
			throw new ValidationError('Missing email/password fields')
		}
		const userEmail = email.toLowerCase()
		return this.userService.getByEmail(userEmail, true)
			.then((user) => {
				if (!user) {
					throw new ConflictError('User not found')
				}
				if (user.role !== 'guest') {
					throw new ConflictError('Guest already has user role')
				}
				return rp({
					method: 'POST',
					uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/sign-up`,
					resolveWithFullResponse: true,
					headers: {
						'Content-Type': 'application/json',
						'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
						country: this.env.getEnvProp('COUNTRY')
					},
					json: true,
					body: {
						email,
						password
					}
				}).then((result) => {
					if (result.statusCode === 200) {
						user.active = false
						user.role = 'user'
						if (!user.provider || user.provider !== 'local') {
							user.provider = 'local'
						}
						return user.save().then(usr => mapper.models.getUser(usr))
					}
					return null
				}).catch((err) => {
					this.logger.error('Sign up error', { additionalInfo: err })
					if (err.error) {
						const parsedError = err.error.constructor === objectConstructor ? err.error : parseError(err.error)
						let errorMessage = err.message
						if (parsedError && parsedError.reason &&
							((parsedError.reason.cause && parsedError.reason.cause.message) || parsedError.reason.message)
						) {
							errorMessage = parsedError.reason.cause ? parsedError.reason.cause.message : parsedError.reason.message
						}
						throw new AuthError(errorMessage)
					}
					throw new ServerError(err.message || err.stack)
				})
			})
	}

	async changeUserEmail (user, newEmail) {
		return rp({
			method: 'POST',
			uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/change-user-email`,
			resolveWithFullResponse: true,
			headers: {
				'Content-Type': 'application/json',
				'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
				country: this.env.getEnvProp('COUNTRY')
			},
			json: true,
			body: {
				email: user.email,
				newEmail
			}
		}).catch((err) => {
			console.log(err.message || err.stack)
			if (err.error) {
				const parsedError = err.error.constructor === objectConstructor ? err.error : parseError(err.error)
				let errorMessage = err.message
				if (parsedError && parsedError.reason &&
					((parsedError.reason.cause && parsedError.reason.cause.message) || parsedError.reason.message)
				) {
					errorMessage = parsedError.reason.cause ? parsedError.reason.cause.message : parsedError.reason.message
				}
				throw new AuthError(errorMessage)
			}
			throw new ServerError(err.message || err.stack)
		})
	}

	async confirmChangeUserEmail (token, userId, code) {
		if (!token || !code) {
			throw new ValidationError('Bad request')
		}
		const bodyToken = token.replace('Bearer ', '')
		const { accessToken } = jwt.decode(bodyToken)
		return rp({
			method: 'POST',
			uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/confirm-user-email`,
			resolveWithFullResponse: true,
			headers: {
				'Content-Type': 'application/json',
				'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
				country: this.env.getEnvProp('COUNTRY')
			},
			json: true,
			body: {
				accessToken,
				code
			}
		}).then((result) => {
			if (result.statusCode === 200) {
				return this.db.User.update({ emailVerified: true }, { where: { id: userId } })
					.then(usr => mapper.models.getUser(usr[1][0]))
			}
			return null
		}).catch((err) => {
			this.logger.error('Change pass error', { additionalInfo: err })
			if (err.error) {
				const parsedError = err.error.constructor === objectConstructor ? err.error : parseError(err.error)
				let errorMessage = err.message
				if (parsedError && parsedError.reason &&
					((parsedError.reason.cause && parsedError.reason.cause.message) || parsedError.reason.message)
				) {
					errorMessage = parsedError.reason.cause ? parsedError.reason.cause.message : parsedError.reason.message
				}
				throw new AuthError(errorMessage)
			}
			throw new ServerError(err.message || err.stack)
		})
	}

	async challengeSignUp (email, temporaryPassword, newPassword, confirmNewPassword) {
		const userEmail = email.toLowerCase()
		const user = await this.userService.getByEmail(userEmail, true)
		if (!user) {
			throw new ValidationError('User not found!')
		}
		if (newPassword !== confirmNewPassword) {
			throw new ValidationError('Password mismatch')
		}
		if (newPassword.length < 8) {
			throw new ValidationError('Password did not conform with policy: length less than 8 symbols')
		}
		return rp({
			method: 'POST',
			uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/challenge-sign-up`,
			resolveWithFullResponse: true,
			body: JSON.stringify({
				email: user.email,
				temporaryPassword,
				newPassword
			}),
			headers: {
				'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
				country: this.env.getEnvProp('COUNTRY')
			}
		}).then((resp) => {
			if (resp && resp.statusCode === 200) {
				if (user.role === 'oldUser') {
					if (user.hasSocial) {
						return this.db.UserSocial.update({ cognitoVerified: true }, { where: { UserId: user.id } })
					}
					return this.db.User.update({ role: 'user', emailVerified: true, active: true }, { where: { id: user.id } })
				}
				return resp
			}
			throw new ServerError(resp.body)
		}).then(() => this.localAuthenticate(user.id, user.email, newPassword)).catch((err) => {
			console.log(err.stack || err.message)
			if (err.error) {
				const parsedError = err.error.constructor === objectConstructor ? err.error : parseError(err.error)
				let errorMessage = err.message
				if (parsedError && parsedError.reason &&
					((parsedError.reason.cause && parsedError.reason.cause.message) || parsedError.reason.message)
				) {
					errorMessage = parsedError.reason.cause ? parsedError.reason.cause.message : parsedError.reason.message
				}
				throw new AuthError(errorMessage)
			}
			throw new ServerError(err.stack || err.message)
		})
	}

	async resetPasswordManual (email) {
		if (!email) {
			throw new ValidationError('Email is empty!')
		}
		const userEmail = email.toLowerCase()
		const user = await this.userService.getByEmail(userEmail, true)
		if (!user) {
			throw new ValidationError('User not found!')
		}
		if (!user.active) {
			throw new ValidationError('User not activated!')
		}
		const code = uuidv4().substring(0, 8)
		return rp({
			method: 'POST',
			uri: `${this.env.getEnvProp('COGNITO_LAMBDA_URI')}/reset-password-confirmed`,
			resolveWithFullResponse: true,
			body: JSON.stringify({
				email: user.email,
				password: code
			}),
			headers: {
				'x-api-key': this.env.getEnvProp('COGNITO_LAMBDA_KEY'),
				country: this.env.getEnvProp('COUNTRY')
			}
		})
			.then(response => ({
				result: response.body,
				url: `https://bookis.com/no/auth?temporaryPassword=${code}&user=${userEmail}`
			}))
			.catch((err) => {
				console.log(err.stack || err.message)
				if (err.error) {
					const parsedError = err.error.constructor === objectConstructor ? err.error : parseError(err.error)
					let errorMessage = err.message
					if (parsedError && parsedError.reason &&
						((parsedError.reason.cause && parsedError.reason.cause.message) || parsedError.reason.message)
					) {
						errorMessage = parsedError.reason.cause ? parsedError.reason.cause.message : parsedError.reason.message
					}
					throw new AuthError(errorMessage)
				}
				throw new ServerError(err.stack || err.message)
			})
	}
}

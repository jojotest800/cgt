const {
	AccessError, DuplicateError, ValidationError
} = require('../../utils').errors
const { mapper } = require('../../utils')

module.exports = {
	authAPI: ({ authService, userService }) => ({
		create: async (req, res) => {
			req.body.provider = 'local'
			if (req.body.role === 'admin') {
				throw new AccessError('admin cannot be created')
			}
			if (!req.body.email) {
				return res.status(403).json({
					error: {
						error_fields: [
							{
								field: 'email',
								message: 'Email is required'
							}
						]
					},
					data: {},
					code: 403
				})
			}
			req.body.email = req.body.email && req.body.email.toLowerCase()
			const user = await userService.getByEmail(req.body.email, true)
			if (req.body.role === 'guest' && user && user.role === req.body.role) {
				return res.status(201).json({
					code: 0,
					data: {
						role: user.role,
						user_id: user.id,
						user: mapper.models.getUser(user)
					}
				})
			}
			if (user && user.active && user.role !== 'guest') {
				throw new DuplicateError('User with the email exists')
			}
			if (req.body.role !== 'guest' && (!req.body.password || req.body.password.length < 8)) {
				throw new ValidationError('Password did not conform with policy: length less than 8 symbols')
			}
			const newUser = await authService.signUp(req.body, req.countryCode)
			if (!newUser || newUser.codeError) {
				return res.status(403).json({
					error: {
						error_fields: [
							{
								field: 'error',
								message: (newUser && newUser.codeError) || 'Something went wrong'
							}
						]
					},
					data: {},
					code: 403
				})
			}
			return res.status(201).json({
				code: 0,
				data: {
					role: newUser.role,
					user_id: newUser.id,
					user: newUser
				}
			})
		},
		confirm: async (req, res) => {
			if (!req.body.email) {
				return res.status(403)
					.json({
						error: {
							error_fields: [
								{
									field: 'email',
									message: 'Email is required'
								}
							]
						},
						data: {},
						code: 403
					})
			}
			if (!req.body.code) {
				return res.status(403)
					.json({
						error: {
							error_fields: [
								{
									field: 'code',
									message: 'Code is required'
								}
							]
						},
						data: {},
						code: 403
					})
			}
			req.body.email = req.body.email.toLowerCase()
			const user = await userService.getByEmail(req.body.email, true)
			if (!user) {
				return res.status(403)
					.json({
						error: {
							error_fields: [
								{
									message: 'User not found!'
								}
							]
						},
						data: {},
						code: 403
					})
			}
			if (user.provider === 'local' && user.active && user.emailVerified) {
				return res.status(403)
					.json({
						error: {
							error_fields: [
								{
									message: 'User already activated!'
								}
							]
						},
						data: {},
						code: 403
					})
			}
			return authService.confirmSignUp(user.id, req.body.email, req.body.code)
				.then(result => res.status(201).json({
					code: 0,
					data: {
						role: result.role,
						user_id: result.id,
						user_guid: result.guid
					}
				}))
				.catch(err => res.status(err.statusCode || 499).json({
					code: err.statusCode || 499,
					message: err.message,
					error: err
				}))
		},
		auth: async (req, res) => {
			if (!req.body.email) {
				return res.status(403)
					.json({
						error: {
							error_fields: [
								{
									field: 'email',
									message: 'Email is required'
								}
							]
						},
						data: {},
						code: 403
					})
			}
			if (!req.body.password) {
				return res.status(403)
					.json({
						error: {
							error_fields: [
								{
									field: 'password',
									message: 'Password is required'
								}
							]
						},
						data: {},
						code: 403
					})
			}
			req.body.email = req.body.email.toLowerCase()
			const user = await userService.getByEmail(req.body.email, true)
			if (!user) {
				return res.status(403)
					.json({
						error: {
							error_fields: [
								{
									message: 'User not found!'
								}
							]
						},
						data: {},
						code: 403
					})
			}
			if (!user.active && !req.body.requestedReactivation) {
				return res.status(403)
					.json({
						error: {
							error_fields: [
								{
									message: 'User not activated!'
								}
							]
						},
						data: {
							active: false
						},
						code: 403
					})
			}
			if (!user.active && req.body.requestedReactivation && user.emailVerified) {
				await authService.reactivateUser(user)
				user.active = true
				await user.save()
			}
			const result = await authService.localAuthenticate(user.id, req.body.email, req.body.password)
			if (!result.token) {
				return res.status(403)
					.json({
						error: result.error,
						data: {},
						code: 403
					})
			}
			return res.status(200).json({ data: result })
		},
		signUpGuest: async (req, res) => authService.signUpGuest(req.body)
			.then(result => res.status(200).json({ code: 0, data: result })),
		refreshToken: async (req, res) => authService.refreshToken(req.body.token, req.body.refreshToken)
			.then(result => res.status(200).json({ code: 0, data: result })),
		googleAuth: async (req, res) => authService.googleAuthenticate(req.body.token, req.countryCode).then((result) => {
			if (!result.token) {
				return res.status(result.statusCode || 403)
					.json({
						error: result.error,
						data: result.data || {},
						code: result.statusCode || 403
					})
			}
			return res.status(200).json({ data: result })
		}),
		facebookAuth: async (req, res) => authService.facebookAuthenticate(req.body.token, req.countryCode).then((result) => {
			if (!result.token) {
				return res.status(result.statusCode || 403)
					.json({
						error: result.error,
						data: result.data || {},
						code: result.statusCode || 403
					})
			}
			return res.status(200).json({ data: result })
		}),
		appleAuth: async (req, res) => authService.appleAuthenticate(
			req.body.token || req.body.id_token,
			{ firstName: req.body.firstName, lastName: req.body.lastName },
			!!req.body.id_token,
			req.countryCode
		)
			.then((result) => {
				if (!result.token) {
					return res.status(result.statusCode || 403)
						.json({
							error: result.error,
							data: result.data || {},
							code: result.statusCode || 403
						})
				}
				if (result.redirect) {
					return res.redirect(result.redirect, 301)
				}
				return res.status(200).json({ data: result })
			}),
		reactivateSocial: async (req, res) => {
			if (!req.body || !req.body.email) {
				return res.status(403)
					.json({
						error: {
							error_fields: [
								{
									field: 'email',
									message: 'Email is required'
								}
							]
						},
						data: {},
						code: 403
					})
			}
			return authService.reactivateSocial(req.body.email).then(result => res.status(200).json({ code: 0, data: result }))
		},
		changePassword: async (req, res) => authService.changePassword(req.headers.authorization, req.body.newPassword, req.body.oldPassword)
			.then(result => res.status(200).json({ code: 0, data: result })),
		resetPassword: async (req, res) => authService.resetPassword(req.body.email)
			.then(result => res.status(200).json({ code: 0, data: result })),
		challengeSignUp: async (req, res) => authService.challengeSignUp(req.body.email, req.body.temporaryPassword, req.body.newPassword, req.body.confirmNewPassword)
			.then(result => res.status(200).json({ code: 0, data: result })),
		confirmResetPassword: async (req, res) => authService.confirmResetPassword(req.body)
			.then(result => res.status(200).json({ code: 0, data: result })),
		resetConfirmationCode: async (req, res) => authService.resendCode(req.body.email)
			.then(result => res.status(200).json({ code: 0, data: result }))
			.catch(err => res.status(err.statusCode || 499).json({
				code: err.statusCode || 499,
				message: err.message,
				error: err
			})),
		confirmNewEmail: async (req, res) => authService.confirmChangeUserEmail(req.headers.authorization, req.user && req.user.id, req.body.code)
			.then(result => res.status(200).json({ code: 0, data: result })),
		generateConfirmationLink: async (req, res) => {
			if (req.headers['api-key'] !== '597f479daa80ed54fbd795a4') {
				return res.status(404).json({ error: 'Code is not correct!' })
			}
			const result = await authService.resetPasswordManual(req.body.email)
			return res.status(200).json(result)
		}
	})
}

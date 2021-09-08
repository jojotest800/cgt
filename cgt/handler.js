const AWS = require('aws-sdk')
const CognitoSDK = require('amazon-cognito-identity-js-node')
const { promisify } = require('bluebird')
const jwt = require('jsonwebtoken')
const rp = require('request-promise')
const FB = require('fb')

AWS.config.region = process.env.AWS_COGNITO_REGION
AWS.CognitoIdentityServiceProvider.AuthenticationDetails =
  CognitoSDK.AuthenticationDetails
AWS.CognitoIdentityServiceProvider.CognitoUserPool = CognitoSDK.CognitoUserPool
AWS.CognitoIdentityServiceProvider.CognitoUser = CognitoSDK.CognitoUser
AWS.CognitoIdentityServiceProvider.RefreshToken = CognitoSDK.CognitoRefreshToken
AWS.CognitoIdentityServiceProvider.CognitoUserAttribute =
  CognitoSDK.CognitoUserAttribute

const getCountryParam = (param, country) => process.env[`${param}_${country.toUpperCase()}`]

function getServiceProvider () {
	return new AWS.CognitoIdentityServiceProvider({
		apiVersion: '2016-04-18',
		region: process.env.AWS_COGNITO_REGION,
		accessKeyId: process.env.ACCESS_KEY_ID,
		secretAccessKey: process.env.SECRET_ACCESS_KEY
	})
}

function getUserPool (country) {
	return new AWS.CognitoIdentityServiceProvider.CognitoUserPool({
		UserPoolId: getCountryParam('AWS_COGNITO_USER_POOL_ID', country),
		ClientId: getCountryParam('AWS_COGNITO_CLIENT_ID', country)
	})
}

const createResponse = (code, resp) => ({
	statusCode: code,
	headers: {
		'Access-Control-Allow-Origin': '*',
		'Access-Control-Allow-Credentials': true
	},
	body: JSON.stringify(resp)
})

module.exports.signUp = async (event, context, callback) => {
	try {
		const { country } = event.headers
		if (!country) {
			throw new Error('country is not specified')
		}

		const { email, password } = JSON.parse(event.body)

    const serviceProvider = getServiceProvider()
		try {
      const adminGetUser = promisify(serviceProvider.adminGetUser)

      const user = await adminGetUser.call(serviceProvider, {
        UserPoolId: getCountryParam('AWS_COGNITO_USER_POOL_ID', country),
        Username: email.toLowerCase(),
      })

      if (user) {
        console.log('User already exists')
        return callback(
          null,
          createResponse(500, { message: `User ${email.toLowerCase()} already exists` })
        )
      }
		} catch (e) {
      if (e.code !== 'UserNotFoundException') {
        throw e
      }
		}

    const userPool = getUserPool(country)

    const signUp = promisify(userPool.signUp)

		const attributes = [{ Name: 'email', Value: email.toLowerCase() }]

		await signUp.call(userPool, email.toLowerCase(), password, attributes, null)

		return callback(
      null,
      createResponse(200, { message: 'user is signed up successfully', status: 200 })
    )
	} catch (reason) {
		console.log('Error: ', reason)
		return callback(
			null,
			createResponse(500, { message: 'Sign up confirmation error', reason })
		)
	}
}

module.exports.confirmSignUp = async (event, context, callback) => {
	try {
		const { country } = event.headers
		if (!country) {
			throw new Error('country is not specified')
		}

		const { email, code } = JSON.parse(event.body)

		const cognitoUser = new AWS.CognitoIdentityServiceProvider.CognitoUser({
			Username: email.toLowerCase(),
			Pool: getUserPool(country)
		})

		const confirmRegistration = promisify(cognitoUser.confirmRegistration)
		await confirmRegistration.call(cognitoUser, code, true)

		return callback(
			null,
			createResponse(200, { message: 'registration is confirmed' })
		)
	} catch (reason) {
		console.log('err', reason)
		return callback(
			null,
			createResponse(500, { message: 'Sign up confirmation error', reason })
		)
	}
}

module.exports.auth = async (event, context, callback) => {
	// eslint-disable-next-line no-param-reassign
	context.callbackWaitsForEmptyEventLoop = false
	try {
		const { country } = event.headers
		if (!country) {
			throw new Error('country is not specified')
		}

		const { accountId, login, password } = JSON.parse(event.body)
		const email = login.toLowerCase()
		console.log('Try to auth ', email)
		const authenticationDetails = new AWS.CognitoIdentityServiceProvider.AuthenticationDetails(
			{
				Username: email,
				Password: password,
			}
		)

		const cognitoUser = new AWS.CognitoIdentityServiceProvider.CognitoUser({
			Username: email,
			Pool: getUserPool(country),
		})

		const { accessToken, error } = await new Promise((resolve, reject) => {
			cognitoUser.authenticateUser(authenticationDetails, {
				onSuccess(result) {
          console.log(result)
					return resolve({
						accessToken: result.getAccessToken().getJwtToken(),
					})
				},
				onFailure(err) {
          console.log('Auth err ', err)
					return reject(err)
				},
			})
		})


		const parsedToken = jwt.decode(accessToken)
		let refreshToken = {}
		let errorSession
		cognitoUser.getSession(function(err, session) {
			if (err) {
				errorSession = err
				return
			}
			console.log('session validity: ', session.isValid())
			refreshToken = session.getRefreshToken()
		})


		if (error || errorSession) {
			return callback(null, createResponse(500, { message: error.message || (errorSession && errorSession.message) }))
		}
		const serviceProvider = getServiceProvider()
		const getUser = promisify(serviceProvider.getUser)
		const user = await getUser.call(serviceProvider, {
			AccessToken: accessToken,
		})

		const fields = ['email']
		fields.forEach(field => {
			const attribute = user.UserAttributes.find(a => a.Name === field)
			if (attribute && attribute.Value) {
				parsedToken[field] = attribute.Value
			}
		})
		parsedToken.accountId = accountId
		parsedToken.accessToken = accessToken

		const date = new Date(0)
		date.setUTCSeconds(parsedToken.exp)
		// Add to token 1 month to expiration
		let newDate = new Date(date)
		newDate = newDate.setMonth(newDate.getMonth()+1)
    parsedToken.exp = Math.floor(newDate / 1000 - 23 * 60 * 60)
		const response = {
			access_token: jwt.sign(parsedToken, getCountryParam('ENCODE_SECRET_KEY', country)),
			refresh_token: refreshToken.token,
			expire_time: newDate
		}
		return callback(null, createResponse(200, response))
	} catch (reason) {
		console.log('err', reason)
		return callback(
			null,
			createResponse(500, { message: 'Auth error', reason })
		)
	}
}

module.exports.changePassword = async (event, context, callback) => {
	try {
		const { accessToken, previousPassword, proposedPassword } = JSON.parse(
			event.body
		)

		const serviceProvider = getServiceProvider()

		const changePassword = promisify(serviceProvider.changePassword)

		await changePassword.call(serviceProvider, {
			AccessToken: accessToken,
			PreviousPassword: previousPassword,
			ProposedPassword: proposedPassword,
		})

		return callback(
			null,
			createResponse(200, { message: 'password changed successfully' })
		)
	} catch (reason) {
		console.log('err', reason)
		return callback(
			null,
			createResponse(500, { message: 'Change password error', reason })
		)
	}
}

module.exports.resetPassword = async (event, context, callback) => {
	try {
		const { country } = event.headers
		if (!country) {
			throw new Error('country is not specified')
		}

		const { email } = JSON.parse(event.body)

		const serviceProvider = getServiceProvider()

		const forgotPassword = promisify(serviceProvider.forgotPassword)
		await forgotPassword.call(serviceProvider, {
			ClientId: getCountryParam('AWS_COGNITO_CLIENT_ID', country),
			Username: email.toLowerCase(),
		})

		return callback(
			null,
			createResponse(200, { message: 'password reset successfully' })
		)
	} catch (reason) {
		console.log('err', reason)
		return callback(
			null,
			createResponse(500, { message: 'Reset password error', reason })
		)
	}
}

module.exports.confirmResetPassword = async (event, context, callback) => {
	try {
		const { country } = event.headers
		if (!country) {
			throw new Error('country is not specified')
		}

		const { password, email, code } = JSON.parse(event.body)

		const serviceProvider = getServiceProvider()

		const confirmForgotPassword = promisify(
			serviceProvider.confirmForgotPassword
		)

		await confirmForgotPassword.call(serviceProvider, {
			ClientId: getCountryParam('AWS_COGNITO_CLIENT_ID', country),
			Username: email.toLowerCase(),
			Password: password,
			ConfirmationCode: code,
		})

		return callback(
			null,
			createResponse(200, { message: 'password confirmed successfully' })
		)
	} catch (reason) {
		console.log('err', reason)
		return callback(
			null,
			createResponse(500, {
				message: 'Reset password confirmation error',
				reason,
			})
		)
	}
}

module.exports.resendConfirmationCode = async (event, context, callback) => {
	try {
		const { country } = event.headers
		if (!country) {
			throw new Error('country is not specified')
		}

		const { email } = JSON.parse(event.body)

		const serviceProvider = getServiceProvider()

		const resendConfirmationCode = promisify(
			serviceProvider.resendConfirmationCode
		)

		await resendConfirmationCode.call(serviceProvider, {
			ClientId: getCountryParam('AWS_COGNITO_CLIENT_ID', country),
			Username: email.toLowerCase(),
		})

		return callback(
			null,
			createResponse(200, {
				message: 'new confirmation code was successfully sent ',
			})
		)
	} catch (reason) {
		console.log('err', reason)
		return callback(
			null,
			createResponse(500, { message: 'Resend confirmation code error', reason })
		)
	}
}

module.exports.facebookLogin = async (event, context, callback) => {
	// eslint-disable-next-line no-param-reassign
	context.callbackWaitsForEmptyEventLoop = false
	try {
		const { country } = event.headers
		if (!country) {
			throw new Error('country is not specified')
		}

		const { token } = JSON.parse(event.body)

		FB.setAccessToken(token)

		const response = await FB.api('/me', {
			fields: ['id', 'email', 'name', 'first_name', 'last_name', 'picture.width(1080)']
		})

		console.log('response', response)

		if (!response.email) {
			return callback(
				null,
				createResponse(500, {
					message:
						"We can't get your email because of it is private or is not bound to your profile",
				})
			)
		}

		AWS.config.credentials = new AWS.CognitoIdentityCredentials({
			IdentityPoolId: getCountryParam('AWS_IDENTITY_POOL_ID', country),
			Logins: {
				'graph.facebook.com': token,
			},
		})

		await AWS.config.credentials.getPromise()

		const res = {
			avatar_url: response.picture && response.picture.data && response.picture.data.url,
			provider_name: 'facebook',
			preferred_username: response.email,
			firstName: response.first_name,
			lastName: response.last_name || '',
			facebookName: response.name,
			email: response.email,
			id: response.id
		}

		return callback(
			null,
			createResponse(200, {
				access_token: jwt.sign(res, getCountryParam('ENCODE_SECRET_KEY', country)),
			})
		)
	} catch (reason) {
		console.log('err', reason)
		return callback(
			null,
			createResponse(500, { message: 'Facebook login error', reason })
		)
	}
}

module.exports.googleLogin = async (event, context, callback) => {
	// eslint-disable-next-line no-param-reassign
	context.callbackWaitsForEmptyEventLoop = false
	try {
		const { country } = event.headers
		if (!country) {
			throw new Error('country is not specified')
		}

		const { token } = JSON.parse(event.body)

		AWS.config.credentials = new AWS.CognitoIdentityCredentials({
			IdentityPoolId: getCountryParam('AWS_IDENTITY_POOL_ID', country),
			Logins: {
				'accounts.google.com': token,
			},
		})

		await AWS.config.credentials.getPromise()

		const response = await rp(
			`https://oauth2.googleapis.com/tokeninfo?id_token=${token}`
		)

		const googleUser = JSON.parse(response)

		const res = {
			avatar_url: googleUser.picture,
			provider_name: 'google',
			preferred_username: googleUser.email,
			firstName: googleUser.given_name,
			lastName: googleUser.family_name || '',
			fullName: googleUser.name,
			email: googleUser.email,
			id: googleUser.sub
		}

		console.log('response', res)

		return callback(
			null,
			createResponse(200, {
				access_token: jwt.sign(res, getCountryParam('ENCODE_SECRET_KEY', country)),
			})
		)
	} catch (reason) {
		console.log('err', reason)
		return callback(
			null,
			createResponse(500, { message: 'Google login error', reason })
		)
	}
}

module.exports.appleLogin = async (event, context, callback) => {
	// eslint-disable-next-line no-param-reassign
	context.callbackWaitsForEmptyEventLoop = false
	try {
		const { country } = event.headers
		if (!country) {
			throw new Error('country is not specified')
		}

		const { token, fullName } = JSON.parse(event.body)

		AWS.config.credentials = new AWS.CognitoIdentityCredentials({
			IdentityPoolId: getCountryParam('AWS_IDENTITY_POOL_ID', country),
			Logins: {
				'appleid.apple.com': token,
			},
		})

		await AWS.config.credentials.getPromise()

		const { email } = jwt.decode(token)

		const res = {
			avatar_url: null,
			provider_name: 'apple',
			preferred_username: email,
			firstName: fullName && fullName.firstName,
			lastName: fullName && fullName.lastName,
			email
		}

		return callback(
			null,
			createResponse(200, {
				access_token: jwt.sign(res, getCountryParam('ENCODE_SECRET_KEY', country)),
			})
		)
	} catch (reason) {
		console.log('err', reason)
		return callback(
			null,
			createResponse(500, { message: 'Google login error', reason })
		)
	}
}

module.exports.signupWithConfirm = async (event, context, callback) => {
	try {
		const { country } = event.headers
		if (!country) {
			throw new Error('country is not specified')
		}

		const { email, password } = JSON.parse(event.body)

		const serviceProvider = getServiceProvider()
		try {
			const adminGetUser = promisify(serviceProvider.adminGetUser)

			const user = await adminGetUser.call(serviceProvider, {
				UserPoolId: getCountryParam('AWS_COGNITO_USER_POOL_ID', country),
				Username: email.toLowerCase(),
			})

			if (user) {
				console.log('User already exists')
				return callback(
					null,
					createResponse(500, { message: `User ${email.toLowerCase()} already exists` })
				)
			}
		} catch (e) {
			if (e.code !== 'UserNotFoundException') {
				throw e
			}
		}

		const adminSignUp = promisify(serviceProvider.adminCreateUser)
		const params = {
			UserPoolId: getCountryParam('AWS_COGNITO_USER_POOL_ID', country),
			Username: email.toLowerCase(),
			UserAttributes: [{ Name: 'email_verified', Value: 'true' }, { Name: 'email', Value: email }],
			MessageAction: 'SUPPRESS',
			TemporaryPassword: password
		}
		await adminSignUp.call(serviceProvider, params)

		return callback(
			null,
			createResponse(200, { message: 'user is signed up successfully', status: 200 })
		)
	} catch (reason) {
		console.log('Error: ', reason)
		return callback(
			null,
			createResponse(500, { message: 'Sign up confirmation error', reason })
		)
	}
}

module.exports.resetPasswordWithConfirm = async (event, context, callback) => {
	try {
		const { country } = event.headers
		if (!country) {
			throw new Error('country is not specified')
		}

		const { email, password } = JSON.parse(event.body)

		const serviceProvider = getServiceProvider()
		const adminGetUser = promisify(serviceProvider.adminGetUser)

		await adminGetUser.call(serviceProvider, {
			UserPoolId: getCountryParam('AWS_COGNITO_USER_POOL_ID', country),
			Username: email.toLowerCase(),
		})

		const adminSignUp = promisify(serviceProvider.adminCreateUser)
		const params = {
			UserPoolId: getCountryParam('AWS_COGNITO_USER_POOL_ID', country),
			Username: email.toLowerCase(),
			UserAttributes: [{ Name: 'email_verified', Value: 'true' }, { Name: 'email', Value: email }],
			MessageAction: 'RESEND',
			TemporaryPassword: password
		}
		await adminSignUp.call(serviceProvider, params)

		return callback(
			null,
			createResponse(200, { message: 'Reset user password successfully', status: 200 })
		)
	} catch (reason) {
		console.log('Error: ', reason)
		return callback(
			null,
			createResponse(500, { message: 'Reset user password error', reason })
		)
	}
}

module.exports.signUpWithChangePassword = async (event, context, callback) => {
	try {
		const { country } = event.headers
		if (!country) {
			throw new Error('country is not specified')
		}

		const { email, temporaryPassword, newPassword } = JSON.parse(event.body)

		const authenticationDetails = new AWS.CognitoIdentityServiceProvider.AuthenticationDetails(
			{
				Username: email,
				Password: temporaryPassword,
			}
		)

		const cognitoUser = new AWS.CognitoIdentityServiceProvider.CognitoUser({
			Username: email,
			Pool: getUserPool(country),
		})

		cognitoUser.setAuthenticationFlowType('USER_SRP_AUTH')

		const { userAttr } = await new Promise((resolve, reject) => {
			cognitoUser.authenticateUser(authenticationDetails, {
				onFailure(err) {
					console.log('Auth err ', err)
					return reject(err)
				},
				newPasswordRequired(userAttributes) {
					// eslint-disable-next-line no-param-reassign
					delete userAttributes.email_verified
					return resolve({
						userAttr: userAttributes,
					})
				}
			})
		})

		const { accessToken } = await new Promise((resolve, reject) => {
			cognitoUser.completeNewPasswordChallenge(newPassword, userAttr, {
				onSuccess(result) {
					console.log(result)
					return resolve({
						accessToken: result.getAccessToken().getJwtToken(),
					})
				},
				onFailure(err) {
					console.log('Auth err ', err)
					return reject(err)
				},
			})
		})

		console.log(accessToken)

		return callback(
			null,
			createResponse(200, { message: 'User has been changed password successfully', status: 200 })
		)
	} catch (reason) {
		console.log('Error: ', reason)
		return callback(
			null,
			createResponse(500, { message: 'Reset user password error', reason })
		)
	}
}

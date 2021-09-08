const { makeInvoker } = require('awilix-express')
const { Router } = require('express')

const { authAPI } = require('./authController')
const { isAuthenticated } = require('../../middleware/auth')

const router = Router()

const api = makeInvoker(authAPI)

router.post('/signUp', api('create'))
router.post('/confirm', api('confirm'))
router.post('/guest/signUp', api('signUpGuest'))
router.post('/login', api('auth'))
router.post('/google/login', api('googleAuth'))
router.post('/facebook/login', api('facebookAuth'))
router.post('/apple/login', api('appleAuth'))
router.post('/token', api('refreshToken'))
router.post('/resetPassword', api('resetPassword'))
router.post('/challengeSignUp', api('challengeSignUp'))
router.post('/confirmResetPassword', api('confirmResetPassword'))
router.post('/resendCode', api('resetConfirmationCode'))
router.post('/changePassword', isAuthenticated(), api('changePassword'))
router.post('/confirmNewEmail', isAuthenticated(), api('confirmNewEmail'))
router.post('/reactivate', api('reactivateSocial'))
router.post('/generateConfirmation', api('generateConfirmationLink'))

module.exports = router

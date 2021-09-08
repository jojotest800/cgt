const { Lifetime, asClass, asValue } = require('awilix')
const authRouter = require('./authRouter')
const authService = require('./authService')

module.exports = {
	load (container) {
		container.register({
			authService: asClass(authService, { lifetime: Lifetime.SINGLETON })
		})

		const app = container.resolve('expressApp')

		app.use('/api/auth', authRouter)
	}
}

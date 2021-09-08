/* eslint-disable no-unused-expressions */
const passwordManager = require('generate-password')

module.exports.cognitoValidation = (password) => {
	let possibleUpperCount = 0
	let possibleLowerCount = 0
	let numberCount = 0
	for (let i = 0; i < password.length; i += 1) {
		Number.isInteger(+password[i]) && (numberCount += 1)
		password[i] === password[i].toUpperCase() && (possibleUpperCount += 1)
		password[i] === password[i].toLowerCase() && (possibleLowerCount += 1)
	}
	return (
		possibleUpperCount - numberCount >= 1 &&
    possibleLowerCount - numberCount >= 1 &&
    numberCount >= 1 &&
    password.length >= 8
	)
}

module.exports.generateCognitoPassword = (length) => {
	let password = ''
	while (!this.cognitoValidation(password)) {
		password = passwordManager.generate({
			length,
			numbers: true,
			uppercase: true,
			excludeSimilarCharacters: true,
			strict: true
		})
	}
	return password
}

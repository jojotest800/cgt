const path = require('path')

const { facebookLogin } = require('../handler')

const dotEnvPath = path.join(__dirname, '../','.env')
console.log(dotEnvPath)
require('dotenv').config({ path: dotEnvPath })

const promisify = async (handler, event, context) => {
  return new Promise((resolve, reject) => {
    handler(event, context, (err, response) => {
      if (err) {
        reject(err)
      } else {
        resolve(response)
      }
    })
  })
}

test('facebook login', async () => {
  jest.setTimeout(100000)
  const event = {
    body: JSON.stringify({
      token: 'EAADkhUsc1NwBAOt3NWdhuWbIdhdmPKhXA9QSaAM7ZBLuRLR16LHNMteZB32UhpiicSp6Pyh1uZC9wuZCFE35cfgrzZCszZBrbpB2Om0czZAq9Dh6FMH2JxWUNLXQ4tO8ZCQPEbCZAuxDQsdqHjc0xJNMYVnvOnOO4iiWWsOcsAODZBVV6FxtwFZC4B2AkobDsmGZAY5UisN8vuAWdHHVclzLLTMpqhZCSASXdPtEZD'
    })
  }
  const result = await promisify(facebookLogin, event, {
    callbackWaitsForEmptyEventLoop: false,
  })
  expect(result.body).toMatchSnapshot()
})

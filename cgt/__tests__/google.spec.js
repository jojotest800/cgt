const path = require('path')

const { googleLogin } = require('../handler')

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

test('google login', async () => {
  jest.setTimeout(100000)
  const event = {
    body: JSON.stringify({
      token: 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImYwNTQxNWIxM2FjYjk1OTBmNzBkZjg2Mjc2NWM2NTVmNWE3YTAxOWUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXpwIjoiMzYwNjgwMjE5Mjg2LWhrMDVhN3IxOGZucmQwcWpxNGozY2gzM2kxdnF1Y3N2LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMzYwNjgwMjE5Mjg2LWhrMDVhN3IxOGZucmQwcWpxNGozY2gzM2kxdnF1Y3N2LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTA2NDY5MjUwMDA0NjAzNDA2MzAwIiwiZW1haWwiOiJobG9wZGltb25AZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiIzYUVndURiS0tCSVMyTy1uV0FGd3pnIiwibmFtZSI6ItCU0LjQvNCwINCi0Y7RgNC40L0iLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EtL0FPaDE0R2lOUHA1dDBBNXNPMmNlQXJoY1lINTB6MEJySDVCYl9EQXlpNWV2VWJBPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6ItCU0LjQvNCwIiwiZmFtaWx5X25hbWUiOiLQotGO0YDQuNC9IiwibG9jYWxlIjoicnUiLCJpYXQiOjE1OTYxOTgxNDgsImV4cCI6MTU5NjIwMTc0OCwianRpIjoiYjU0ODMyNTk1NzMzNjJlYmJkNTlhOWU3MjM5ZDhkYTMxMTdkZmQ1MCJ9.YTFnEe1EYyvs2TciIdEmuTDX0O5LyctnQpDQE7-G1-9FwUPQ_TWTdA9XEpbgOh9RhFMur6R5kX3S1ewka2OAn73NvyED9qZrU0V_n4iANv5eRR3myxUjBtCsly3e6VKr5jxDWJQTZ3HcPpFaFkFCHhQWmWCVtImRUIvRoeOtqkbwutxENBfqSL_yXfOgK7RjaYMqYQ_MQ3P1VNc5DdbKWRBgfCHHE3DuTmA-AEFThdUtnZWksLB7S-0JxJ5yNuzoZ_iS6We_trHcyIGwqMU59cAZjno-Fy3mGUaq9lyUyyXfONZ0VtYma27sfE31_3Fkz3bEgimQixTc7RWr3ncfSw'
    })
  }
  const result = await promisify(googleLogin, event, {
    callbackWaitsForEmptyEventLoop: false,
  })
  expect(result.body).toMatchSnapshot()
})

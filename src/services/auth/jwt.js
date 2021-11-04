import jwt from 'jsonwebtoken'

export const JWTAuthentication = async user => {
    const accesToken = await generateJWT({ _id: user._id })
    return accesToken
}

const generateJWT = payload => 
new Promise((resolve, reject)=> 
    jwt.sign(payload, process.env.JWT_SECRET, {expiresIn:"1 week"}, (error,token) => {
        if(error) reject(error)
        else resolve(token)
    })
    )

export const verifyJWT = token =>
new Promise((res, rej) =>
      jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => {
        if (err) rej(err)
        else res(decodedToken)
      })
    )    
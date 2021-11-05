import jwt from 'jsonwebtoken'
import createHttpError from 'http-errors'
import UserModel from '../users/schema.js'


export const JWTAuthentication = async user => {
    const accessToken = await generateJWT({ _id: user._id })
    const refreshToken = await generateRefreshJWT({ _id: user._id })
    user.refreshToken = refreshToken
    await user.save()
    return { accessToken, refreshToken }
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
 const generateRefreshJWT = payload =>  
 new Promise((resolve, reject) => 
  jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {expiresIn:"7 days"}, (error,token) => {
   if(error) reject(error)
   else resolve(token)
 }))  
 
  const verifyRefreshJWT = token => 
  new Promise((res, rej) => 
  jwt.verify(token, process.env.JWT_REFRESH_SECRET, (error, decodedToken) => 
  {  if (error) rej(error) 
    else res(decodedToken)
   }))



    export const verifyRefreshAndGenerateTokens = async actualRefreshToken => {
      // 1. Check the validity (exp date and integrity)
      const decodedRefreshToken = await verifyRefreshJWT(actualRefreshToken)
    
      // 2. If the token is valid we are going to check if it is in db
      const user = await UserModel.findById(decodedRefreshToken._id)
    
      if (!user) throw createHttpError(404, "User not found")
    
      // 3. If we find the token we need to compare it to the actualRefreshToken
      if (user.refreshToken && user.refreshToken === actualRefreshToken) {
        // 4. If everything is fine we are going to generate a new pair of tokens (and we are storing new refreshtoken in db)
    
        const { accessToken, refreshToken } = await JWTAuthentication(user)
    
        // 5. Return the tokens
        return { accessToken, refreshToken }
      } else throw createHttpError(401, "Refresh token not valid!")
    }
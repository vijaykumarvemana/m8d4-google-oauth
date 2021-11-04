import express from 'express'
import createHttpError from 'http-errors'
import UserModel from './schema.js'

import { JWTAuthMiddleware } from "../auth/token.js"
import { JWTAuthentication} from "../auth/jwt.js"



const userRouter = express.Router()

userRouter.get("/", JWTAuthMiddleware, async(req, res , next) => {
    try {
        const users = await UserModel.find()
        res.send(users)
    } catch (error) {
      next(error)  
    }
})

userRouter.get("/:userID", JWTAuthMiddleware, async(req, res , next) => {
    try {
        const userId = req.params.userID
        const user = await UserModel.findById(userId)
        if(user){
            res.send(user)
        }else{
            next(createHttpError(404, `user with ${userId} not found!`))
        }
    } catch (error) {
      next(error)  
    }
})

userRouter.post("/register",  async(req, res , next) => {
    try {
        const user = new UserModel(req.body)
        const {_id} = await user.save()
        res.send({_id})
        
    } catch (error) {
      next(error)  
    }
})

userRouter.put("/:userID", JWTAuthMiddleware, async(req, res , next) => {
    try {
        const userId = req.params.userID
        const modifiedUser = await UserModel.findByIdAndUpdate(userId, req.body, {
            new:true,
        })

        if(modifiedUser){
            res.send(modifiedUser)
        }else{
            next(createHttpError(404,`user with id ${userId} not found!`))
        }
        
    } catch (error) {
      next(error)  
    }
})

userRouter.delete("/:userID", JWTAuthMiddleware,  async(req, res , next) => {
    try {
        const userId = req.params.userID
        const deletedUser = await UserModel.findByIdAndDelete(userId)
        
        if(deletedUser){
          res.status(204).send()
        }else{
            next(createHttpError(404, `user with id ${userId} not found!`))
        }
    } catch (error) {
      next(error)  
    }
})

// userRouter.post("/register", async (req,res,next) =>{
//     try {
//         const
//     } catch (error) {
//         next()
//     }
// })

userRouter.post("/login", async (req, res, next) => {
    try {
      
      const { email, password } = req.body
  
    
      const user = await UserModel.checkCredentials(email, password)
  
      if (user) {
      
        const accessToken = await JWTAuthentication(user)
  
        
        res.send({ accessToken })
      } else {
        next(createHttpError(401, "Credentials are not correct!"))
      }
    } catch (error) {
      next(error)
    }
  })
  

export default userRouter
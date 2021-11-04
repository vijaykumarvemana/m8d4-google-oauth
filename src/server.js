import express from 'express'
import cors from 'cors'
import mongoose from 'mongoose'
import passport from 'passport'
import GoogleStrategy from './services/auth/oauth.js'
import blogsRouter from './services/index.js'
import reviewRouter  from './services/reviews/index.js'
import authorRouter from './services/authors/index.js'
import userRouter from './services/users/index.js'
import listEndpoints from 'express-list-endpoints'
import { notFoundHandler, badRequestHandler, genericErrorHandler, unauthorizedHandler, forbiddenHandler} from './errorhandlers.js'


const server = express()
const port = process.env.PORT || 3001

passport.use('google', GoogleStrategy)

server.use(cors())
server.use(express.json())
server.use(passport.initialize())


server.use("/blogPosts", blogsRouter)
 server.use("/reviews", reviewRouter)
server.use("/authors", authorRouter)
server.use("/users", userRouter)


server.use(notFoundHandler)
server.use(badRequestHandler)
server.use(unauthorizedHandler)
server.use(genericErrorHandler)


mongoose.connect(process.env.MDB_CONNECTION)

mongoose.connection.on("connected", () => {
    console.log("Successfully connected to mongoDB")
    server.listen(port, () => {
        console.table(listEndpoints(server))
        console.log("Server running on port:", port)
    })
})

mongoose.connection.on("error", err => {
    console.log(err)
})



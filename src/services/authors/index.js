import express from 'express'
import createHttpError from 'http-errors'
import AuthorModel from './schema.js'



const authorRouter = express.Router()

authorRouter.get("/", async(req, res , next) => {
    try {
        const authors = await AuthorModel.find()
        res.send(authors)
    } catch (error) {
      next(error)  
    }
})

authorRouter.get("/:authorID", async(req, res , next) => {
    try {
        const authorId = req.params.authorID
        const author = await AuthorModel.findById(authorId)
        if(author){
            res.send(author)
        }else{
            next(createHttpError(404, `author with ${authorId} not found!`))
        }
    } catch (error) {
      next(error)  
    }
})

authorRouter.post("/", async(req, res , next) => {
    try {
        const author = new AuthorModel(req.body)
        const {_id} = await author.save()
        res.send({_id})
        
    } catch (error) {
      next(error)  
    }
})

authorRouter.put("/:authorID", async(req, res , next) => {
    try {
        const authorId = req.params.authorID
        const modifiedAuthor = await AuthorModel.findByIdAndUpdate(authorId, req.body, {
            new:true,
        })

        if(modifiedAuthor){
            res.send(modifiedAuthor)
        }else{
            next(createHttpError(404,`author with id ${authorId} not found!`))
        }
        
    } catch (error) {
      next(error)  
    }
})

authorRouter.delete("/:authorID", async(req, res , next) => {
    try {
        const authorId = req.params.authorID
        const deletedAuthor = await AuthorModel.findByIdAndDelete(authorId)
        
        if(deletedAuthor){
          res.status(204).send()
        }else{
            next(createHttpError(404, `author with id ${authorId} not found!`))
        }
    } catch (error) {
      next(error)  
    }
})

export default authorRouter
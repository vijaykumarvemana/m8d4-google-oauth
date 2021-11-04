import express from 'express'
import createHttpError from 'http-errors'
import ReviewModel from './schema.js'


const reviewRouter = express.Router()


reviewRouter.get("/", async(req, res , next) => {
    try {
        const reviews = await ReviewModel.find()
        res.send(reviews)
    } catch (error) {
      next(error)  
    }
})

reviewRouter.get("/:reviewID", async(req, res , next) => {
    try {
        const reviewId = req.params.reviewID
        const review = await ReviewModel.findById(reviewId)
        if(review){
            res.send(review)
        }else{
            next(createHttpError(404, `review with ${reviewId} not found!`))
        }
    } catch (error) {
      next(error)  
    }
})

reviewRouter.post("/", async(req, res , next) => {
    try {
        const review = new ReviewModel(req.body)
        const {_id} = await review.save()
        res.send({_id})
        
    } catch (error) {
      next(error)  
    }
})

reviewRouter.put("/:reviewID", async(req, res , next) => {
    try {
        const reviewId = req.params.reviewID
        const modifiedreview = await ReviewModel.findByIdAndUpdate(reviewId, req.body, {
            new:true,
        })

        if(modifiedreview){
            res.send(modifiedreview)
        }else{
            next(createHttpError(404,`review with id ${reviewId} not found!`))
        }
        
    } catch (error) {
      next(error)  
    }
})

reviewRouter.delete("/:reviewID", async(req, res , next) => {
    try {
        const reviewId = req.params.reviewID
        const deletedReview = await ReviewModel.findByIdAndDelete(reviewId)
        
        if(deletedReview){
          res.status(204).send()
        }else{
            next(createHttpError(404, `review with id ${reviewId} not found!`))
        }
    } catch (error) {
      next(error)  
    }
})


export default reviewRouter


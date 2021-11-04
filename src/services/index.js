import express from 'express'
import createHttpError from 'http-errors'
import BlogPostModel from  '../services/schema.js'
import ReviewModel from '../services/reviews/schema.js'
import AuthorsModel from '../services/authors/schema.js'
import { basicAuthMiddleware } from './auth/basic.js'




const blogsRouter = express.Router()


blogsRouter.get("/", async(req, res , next) => {
    try {
        const blogPosts = await BlogPostModel.find()
        .populate({path: "authors users", select: "name first_name"})
        res.send( blogPosts)
    } catch (error) {
      next(error)
    }
})

blogsRouter.get("/:blogID", async(req, res , next) => {
    try {
        const blogId = req.params.blogID
        const blogPost = await BlogPostModel.findById(blogId)
        if(blogPost){
            res.send(blogPost)
        }else{
            next(createHttpError(404, `blogpost with ${blogId} not found!`))
        }
    } catch (error) {
      next(error)  
    }
})

blogsRouter.post("/", async(req, res , next) => {
    try {
        const blogPost = new BlogPostModel(req.body)
        const {_id} = await blogPost.save()
        res.send({_id})
        
    } catch (error) {
      next(error)  
    }
})

blogsRouter.put("/:blogID", async(req, res , next) => {
    try {
        const blogId = req.params.blogID
        const modifiedBlogPost = await BlogPostModel.findByIdAndUpdate(blogId, req.body, {
            new:true,
        })

        if(modifiedBlogPost){
            res.send(modifiedBlogPost)
        }else{
            next(createHttpError(404,`blogpost with id ${blogId} not found!`))
        }
        
    } catch (error) {
      next(error)  
    }
})

blogsRouter.delete("/:blogID", async(req, res , next) => {
    try {
        const blogId = req.params.blogID
        const deletedBlog = await BlogPostModel.findByIdAndDelete(blogId)
        
        if(deletedBlog){
          res.status(204).send()
        }else{
            next(createHttpError(404, `blodpost with id ${blogId} not found!`))
        }
    } catch (error) {
      next(error)  
    }
})

blogsRouter.get("/me/stories", basicAuthMiddleware, async(req, res, next) => {
  try {
    const blogPosts = await BlogPostModel.find()
    .populate({path: "users", select: "first_name"})  
    res.send( blogPosts)
} catch (error) {
  next(error)
}
})

blogsRouter.post("/:blogID/reviews", async (req, res, next) => {
    try {
        
        const review = await ReviewModel.findById(req.body.reviewID, {_id:0})

        if(review){

            const reviewToInsert = {...review.toObject()}

            const updateReview = await BlogPostModel.findByIdAndUpdate(
                req.params.blogID,
                {$push: {review: reviewToInsert}},
                {new: true},
            )

            if(updateReview){
                res.send(updateReview)
                }else{
                    next(createHttpError(404, `blogpost not found!`))
                }
            }else{
                next(createHttpError(404, `review not found!`))
            }
            }catch(error) {
        next(error)
    }
}
)

blogsRouter.get("/:blogID/reviews", async (req, res, next) => {
    try {
      const blog = await BlogPostModel.findById(req.params.blogID)
      if (blog) {
        res.send(blog.review)
      } else {
        next(createHttpError(404, `blog with id ${req.params.blogID} not found!`))
      }
    } catch (error) {
      next(error)
    }
  })
  blogsRouter.get("/:blogID/reviews/:reviewID", async (req, res, next) => {
    try {
      const review = await BlogPostModel.findById(req.params.blogID)
      if (blog) {
        const reviewa = blog.review.find(review => review._id.toString() === req.params.reviewID) // I CANNOT compare an ObjectId (_id) with a string, _id needs to be converted into a string
        if (reviewa) {
          res.send(reviewa)
        } else {
          next(createHttpError(404, `review with id ${req.params.reviewID} not found`))
        }
      } else {
        next(createHttpError(404, `blog with id ${req.params.blogID} not found!`))
      }
    } catch (error) {
      next(error)
    }
  })


  blogsRouter.put("/:blogID/reviews/:reviewID", async (req, res, next) => {
    try {
      
      const blog = await BlogPostModel.findById(req.params.blogID) // blog is a MONGOOSE DOCUMENT not a normal plain JS object
  
      if (blog) {
        const index = blog.review.findIndex(r => r._id.toString() === req.params.reviewID)
  
        if (index !== -1) {
          blog.review[index] = { ...blog.review[index].toObject(), ...req.body }
          await blog.save()
          res.send(blog)
        } else {
          next(createHttpError(404, `Review with id ${req.params.reviewID} not found`))
        }
      } else {
        next(createHttpError(404, `blog with id ${req.params.blogID} not found!`))
      }
    } catch (error) {
      next(error)
    }
  })

  blogsRouter.delete("/:blogID/reviews/:reviewID", async (req, res, next) => {
    try {
      const blog = await BlogPostModel.findByIdAndUpdate(
        req.params.blogID, 
        { $pull: { review: { _id: req.params.reviewID } } }, 
        { new: true } 
      )
      if (blog) {
        res.send(blog)
      } else {
        next(createHttpError(404, `blog with id ${req.params.blogID} not found!`))
      }
    } catch (error) {
      next(error)
    }
  })
  
export default blogsRouter


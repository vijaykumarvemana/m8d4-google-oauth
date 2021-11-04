import mongoose from 'mongoose'
const { Schema, model } = mongoose
import reviewSchema from '../services/reviews/schema.js'


const blogPostSchema = new Schema(
      
    {
       category: {type: String, required: true},
       title: {type: String, required: true},
       cover: {type: String, required: true},
       readTime: {
           value: {type: Number, required:true},
           unit: {type: String, required: true},
       },
       authors: [{
             type: Schema.Types.ObjectId, ref: "Author"
          
       }],
       users: [{
           type: Schema.Types.ObjectId, ref: "User"
       }],
       content: {type: String, required: true},
      reviews: [{
        comment: String,
        rate: Number,
      }
         
      ],
    },
    
       {
           timestamps: true,
       }
)

export default model("BlogPost", blogPostSchema)

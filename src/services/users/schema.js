import mongoose from 'mongoose'

const { Schema, model } = mongoose
import bcrypt from 'bcrypt'



const userSchema = new Schema (
    {
        first_name: { type: String, required: true},
        last_name: { type: String, required: true},
        email: {type: String, required: true},
        password: {type: String},
        googleId: {type: String},
    },
    {
        timestamps: true,
    }
) 

userSchema.pre("save", async function(next){
    const user = this
    console.log(user)
    const plainpassword = user.password
    console.log(plainpassword)
    if(user.isModified("password")){
        user.password = await bcrypt.hash(plainpassword, 10)
        console.log(user.password)
    }
    next()
})

userSchema.methods.toJSON = function(){
    const user = this
    const userObject = user.toObject()
    delete userObject.password
    delete userObject.createdAt
    delete userObject.updatedAt
    delete userObject.__v

    return userObject
}

userSchema.statics.checkCredentials = async function (email, plainpassword) {
    
    const user = await this.findOne({ email }) 
  
    if (user) {
      
      const isMatch = await bcrypt.compare(plainpassword, user.password)
   
      if (isMatch) return user
      else return null 
    } else return null 
}

export default model("User", userSchema)
import passport from 'passport';
import GoogleStrategy from 'passport-google-oauth20'
import UserModel from "../users/schema.js"
import { JWTAuthentication } from './jwt.js';
const googleStrategy = new GoogleStrategy({     
    clientID: process.env.OAUTH_CLIENT_ID,
    clientSecret: process.env.OAUTH_CLIENT_SECRET,
    callbackURL: `${process.env.API_URL}/users/googleRedirect`,
},
async (accesToken, googleProfile, passportNext) => {
    try{
        console.log(googleProfile);

        const user = await UserModel.findOne({googleId: googleProfile.id});
        if(user){
            const token = await JWTAuthentication(user);
            passportNext(null, {token});
        }else{
            const newUser = {
            first_name: googleProfile.name.givenName,
            last_name: googleProfile.name.familyName,
            email: googleProfile.emails[0].value,
            googleId: googleProfile.id,
              }
      
              const createdUser = new UserModel(newUser)
              const savedUser = await createdUser.save()
      
              const token = await JWTAuthentication(savedUser)
      
              passportNext(null, { token})
        }
    }catch(error){
        passportNext(error, null)
    }
});

passport.serializeUser(function(data, passportNext){
    passportNext(null, data)}
    )

export default googleStrategy
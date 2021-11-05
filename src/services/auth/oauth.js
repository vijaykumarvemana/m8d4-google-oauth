import passport from 'passport';
import GoogleStrategy from 'passport-google-oauth20'
import UserModel from "../users/schema.js"
import { JWTAuthentication } from './jwt.js';
const googleStrategy = new GoogleStrategy({     
    clientID: process.env.GOOGLE_OAUTH_ID,
    clientSecret: process.env.GOOGLE_OAUTH_SECRET,
    callbackURL: process.env.API_URL,
},
async (accessToken, refreshToken, googleProfile, passportNext) => {
    try{
        console.log(googleProfile);

        const user = await UserModel.findOne({googleId: googleProfile.id});
        if(user){
            const tokens = await JWTAuthentication(user);
            passportNext(null, {tokens});
        }else{
            const newUser = {
            first_name: googleProfile.name.givenName,
            last_name: googleProfile.name.familyName,
            email: googleProfile.emails[0].value,
            googleId: googleProfile.id,
              }
      
              const createdUser = new UserModel(newUser)
              const savedUser = await createdUser.save()
      
              const tokens = await JWTAuthentication(savedUser)
      
              passportNext(null, { tokens})
        }
    }catch(error){
        passportNext(error, null)
    }
});

passport.serializeUser(function(data, passportNext){
    passportNext(null, data)}
    )

export default googleStrategy
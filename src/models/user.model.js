import mongoose, { Mongoose, Schema } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const userSchema = new Schema(
    {
        username: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
            index: true,
        },
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
        },
        fullName: {
            type: String,
            required: true,
            trim: true,
            index: true,
        },
        avatar: {
            type: String,            //cloudinary URL 
            required: true,
        },
        coverimage: {
            type: String,            //cloudinary URL
        },
        watchHistory: [
            {
                type: Schema.Types.ObjectId,
                ref: "Video",

            }
        ],
        password: {
            type: String,
            required: [true, "Password is required"],
        },
        refreshToken: {
            type: String,
        },

    },
    {
        timestamps: true,
    }

)

//hook - save hone se just pehle password encrypt ho jaye
userSchema.pre("save",async function(next){
    if(!this.isModified("password")) return next();         

    this.password = bcrypt.hash(this.password, 10)           //encrypt   
    next()
})

userSchema.methods.isPasswordCorrect = async function(password){
    return await bcrypt.compare(password, this.password)
}

userSchema.methods.generateAccessToken = function(){
    return jwt.sign(                              //sign method is used to generate token 
        {
            _id: this._id,                 //payload(kaun kaun sa info rakho)...      , this._id is coming from DB
            email: this.email,
            username: this.username,
            fullName: this.fullName
        },
        process.env.ACCESS_TOKEN_SECRET,     
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }       
    )
}
userSchema.methods.generateRefreshToken = function(){
    return jwt.sign(                              //sign method is used to generate token 
        {
            _id: this._id,                 //payload(kaun kaun sa info rakho)...      , this._id is coming from DB
        },
        process.env.REFRESH_TOKEN_SECRET,     
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }       
    )
}

export const User = Mongoose.model("User", userSchema); 
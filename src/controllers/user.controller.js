import { asyncHandler } from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js";
import {User} from "../models/user.model.js";
import {uploadOnCloudinary} from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefereshTokens = async (userId) => {
  try {
    const user = await User.findById(userId)
    const accessToken = user.generateAccessToken()
    const refreshToken = user.generateRefreshToken()
    
    user.refreshToken = refreshToken   //storing the refresh token in DB(encoded form)
    await user.save({ validateBeforeSave: false })   

    return {accessToken, refreshToken}

  } catch (error) {
    throw new ApiError(500, "Something went wrong while generating refresh and access tokens")
  }
}




//register the user
const registerUser = asyncHandler(async (req, res) => {
  //get user detail from frontend 
  //validation - not empty
  //check if user already exists: username , email
  //check for images, check for avatar
  //upload them to cloudinary, avatar
  //create user object(as mongoDb is nosql DB) - create entry in DB
  //remove password and refresh token field from response
  //check for user creation 
  //return res

  
  const{fullName, email, username, password} = req.body
  //console.log("email", email);

  //2
  if(
    [fullName, email, username, password].some((field) => 
      field?.trim() === "")
  ){
    throw new ApiError(400, "All fields are required")
  }


  //3
  const existedUser = await User.findOne({
    $or: [{ username },{ email }]
  })

  if(existedUser){
    throw new ApiError(409, "User with email or username already exists")
  }

  //4
  //req.body   - by express, but since we have added multer middleware, we have req.files
  const avatarLocalPath = req.files?.avatar[0]?.path;               //multer ne jo local server par avatar upload kiya hai, uska path mil jyga
  //const coverImageLocalPath = req.files?.coverImage[0]?.path; 
  

  //handling undefined scenario
  let coverImageLocalPath;
  if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
    coverImageLocalPath = req.files.coverImage[0].path
  }
  
  if(!avatarLocalPath){                      //
    throw new ApiError(400, "Avatar file is required")
  }


  //5
  const avatar = await uploadOnCloudinary(avatarLocalPath)
  const coverImage = await uploadOnCloudinary(coverImageLocalPath)

  if(!avatar){
    throw new ApiError(400, "Avatar file is required")
  }

  //6
  //entry in DB
  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase()
  })
  //console.log(password);

  //7
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"               //password and refreshToken field removed from response
  )


  //8
  if(!createdUser){
    throw new ApiError(500, "Something went wrong while registering the user")
  }


  //9
  return res.status(201).json(new ApiResponse(200, createdUser, "User registered Successfully"))



})  


const loginUser = asyncHandler(async (req, res) => {

  //req body -> data(req.body se data le aao)
  //username or email(based access)
  //find the user 
  //password check(if not correct then print wrong password)
  //generate access and refresh token
  //send(token in) cookies (secure)
  //send response

  const {email, username, password} = req.body
  console.log(email);

  if(!username && !email){
    throw new ApiError(400, "Username or email is required")
  }

  const user = await User.findOne({
    $or: [{username}, {email}]          //find karega ek value, ya to username ke base par ya email ke base par
  })

  if(!user){
    throw new ApiError(404, "User does not exist")
  }

  //User is the object of mongoose 
  const isPasswordValid = await user.isPasswordCorrect(password) 

  if(!isPasswordValid){
    throw new ApiError(401, "Invalid user credentials")
  }

  const {accessToken, refreshToken} = await generateAccessAndRefereshTokens(user._id)
   
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"               
  )

  //send cookies
  const options = {
    httpOnly: true,               //true - cookies can be modiefied from server only, not from frontend
    secure: true
  }

  return res.status(200)
  .cookie("accessToken",accessToken, options)
  .cookie("refreshToken", refreshToken, options)
  .json(
    new ApiResponse(
      200,
      {
        user: loggedInUser, accessToken, refreshToken      //for additional requirements
      },

      "User logged in successfully"
      
    )
  )

})



const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id, 
    {                                             //kya update karna hai
      $set: { 
        refreshToken: undefined                   
      } 
    }, 
    {
      new: true
    }
  )
  const options = {
    httpOnly: true,
    secure: true
  }


  return res
  .status(200)
  .clearCookie("accessToken", options)
  .clearCookie("refreshToken", options)
  .json(new ApiResponse(200, {}, "User logged Out"))
})
 


//setting up refresh and Access token
const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken     //incoming refresh token from user

  if(!incomingRefreshToken){
    throw new ApiError(401, "Unauthorized request")
  }

  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,                //token
      process.env.REFRESH_TOKEN_SECRET     //secret 
    )
  
    //note: In user model, while generating refresh token we have access of _id, so we can use it to generate user info.
    const user = await User.findById(decodedToken?._id)
  
    if(!user){
      throw new ApiError(401, "Invalid refresh token")
    }
  
    if(incomingRefreshToken !== user?.refreshToken){
      throw new ApiError(401, "Refresh Token is expired or used")
    }
  
    //token must be correct now
    const options = {
      httpOnly: true,
      secure: true
    }
    //generate new tokens
    const {accessToken,newRefreshToken} = await generateAccessAndRefereshTokens(user._id)
  
  
    //send response 
    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", newRefreshToken, options)
    .json(new ApiResponse(200, {accessToken, refreshToken: newRefreshToken}, "Access token refreshed"))

  } catch (error) {
      throw new ApiError(401, error?.message || "Invalid refresh token")
  }




})


const changeCurrentPassword = asyncHandler(async(req, res) => {
  //user already logged in hai ya nhi yeh check karne ke liye verifyJWT middleware use kar lenge

  const {oldPassword, newPassword} = req.body
  
  //req.user = user; (from auth.middleware.js)
  const user = await User.findById(req.user?._id)
  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

  if(!isPasswordCorrect){
    throw new ApiError(400, "Invalid old password")
  }

  user.password = newPassword      // not saved currently
  await user.save({ validateBeforeSave: false })    //Saves the user document to the database.

  return res
  .status(200)
  .json(new ApiResponse(200, {}, "Password changed successfully"))


})

const getCurrentUser = asyncHandler(async(req, res) => {
  return res
  .status(200)
  .json(new ApiResponse(
    200, 
    req.user, 
    "User fetched successfully"
  ))
})


//NOTE: if updating a file, create a different controller for better approach 

const updateAccountDetails = asyncHandler(async(req, res) => {
  const {fullName, email} = req.body

  if(!fullName || !email){
    throw new ApiError(400, "All field are required")
  }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        fullName,
        email: email,
      }
    },
    {new: true}              //update hone ke baad jo information hai wo return hogi

  ).select("-password")
  
  return res
  .status(200)
  .json(new ApiResponse(200, user, "Account details updated successfully"))


})

const updateUserAvatar = asyncHandler(async(req, res) =>
{
  const avatarLocalPath = req.file?.path              //multer ne jo local server par avatar upload kiya hai, uska path mil jyga
  
  if(!avatarLocalPath){                      //
    throw new ApiError(400, "Avatar file is missing")
  }

  //ToDo: delete old image 
  const avatar = await uploadOnCloudinary(avatarLocalPath)

  if(!avatar.url){
    throw new ApiError(400, "Error while uploading avatar")
  }

  const user = await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        avatar: avatar.url
      }
    },
    {new: true}
  ).select("-password")

  return res
    .status(200)
    .json(new ApiResponse(200, user, "Avatar image updated successfully"))
  

})

const updateUserCoverImage = asyncHandler(async(req, res) =>
  {
    const coverImageLocalPath = req.file?.path              //multer ne jo local server par avatar upload kiya hai, uska path mil jyga
    
    if(!coverImageLocalPath){                      //
      throw new ApiError(400, "Cover image file is missing")
    }
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
  
    if(!coverImage.url){
      throw new ApiError(400, "Error while uploading cover image")
    } 
  
    const user = await User.findByIdAndUpdate(
      req.user._id,
      {
        $set: {
          coverImage: coverImage.url
        }
      },
      {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200, user, "Cover image updated successfully"))
  
})

const getUserChannelProfile = asyncHandler(async(req, res) => {
  const {username} = req.params
  if(!username?.trim()){
    throw new ApiError(400, "Username is missing")
  }

  const channel = await User.aggregate([
    {
      $match: {
        username: username?.toLowerCase()
      }
    },

    {
      $lookup: {                              //Joins the matched user with the subscriptions 
        from: "subscriptions",
        localField: "_id",               //For each user, their _id is used in the join.
        foreignField: "channel",     //MongoDB checks which documents in subscriptions have a channel field that matches the user's _id.        
        as: "subscribers"            //result will be stored in a new field called subscribers(this will be an array of object)
      }
    },

    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "subscriber",
        as: "subscribedTo"
      }
    },

    {
      $addFields: {
        subscribersCount: {
          $size: "$subscribers"           //Count of subscribers
        },

        channelsSubscribedToCount: {
          $size: "$subscribedTo"         //Count of channels subscribed to
        },

        isSubscribed: {
          $cond: {
            if: {$in: [req.user?._id, "$subscribers.subscriber"]},  //Check if the user is in the subscribers array
            then: true,
            else: false
          }
        }
      }
    },

    {
      $project: {            //what to show in the response
        fullName: 1,
        username: 1,
        subscribersCount: 1,
        channelsSubscribedToCount: 1,
        isSubscribed: 1,
        avatar: 1,
        coverImage: 1,
        email: 1
      }
    }
  ])

  if(!channel?.length){
    throw new ApiError(404, "Channel does not exists")
  }

  return res
  .status(200)
  .json(
    new ApiResponse(200, channel[0], "User channel fetched successfully")
  )

})

export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccountDetails,
  updateUserAvatar,
  updateUserCoverImage,
  getUserChannelProfile
 }
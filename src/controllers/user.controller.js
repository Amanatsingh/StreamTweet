import { asyncHandler } from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js";
import {User} from "../models/user.model.js";
import {uploadOnCloudinary} from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";

const generateAccessAndRefereshTokens = async (userId) => {
  try {
    const user = await User.findById(userId)
    const accessToken = user.generateAccessToken()
    const refreshToken = user.generateRefreshToken()
    
    user.refreshToken = refreshToken   //storing the refresh token in DB
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

  if(!username || !email){
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
 



export { 
  registerUser,
  loginUser,
  logoutUser
 }
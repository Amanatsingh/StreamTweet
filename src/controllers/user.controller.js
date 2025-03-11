import { asyncHandler } from "../utils/asyncHandler.js";

//register the user
const registerUser = asyncHandler(async (req, res) => {
   res.status(200).json({
    message: "chai aur code"
  })
})         

export { registerUser }
const asyncHandler = (requestHandler) => {
<<<<<<< HEAD
    return (req,res,next) => {
=======
    (req,res,next) => {
>>>>>>> ed8a106c2e0e37e41ac017fb9fe64c4204e25267
        Promise.resolve(requestHandler(req,res,next)).catch((err) => next(err))
    }
}



export { asyncHandler }

// const asyncHandler = (fn) => async(req,res,next) => {                           //HIGHER ORDER FUNCTION
//     try {
//         await fn(req,res,next)
//     } catch (error) {
//         res.status(error.code || 500).json({
//             success: false,
//             message: error.message
//         })
//     }

// }
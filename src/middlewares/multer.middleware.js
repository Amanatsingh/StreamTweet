import multer from "multer";

const storage = multer.diskStorage({                               //for storage
    destination: function (req, file, cb) {
      cb(null, "./public/temp")
    },
    filename: function (req, file, cb) {
      cb(null, file.originalname)             //we can also use -> cb(null, file.fieldname + '-' + uniqueSuffix) for unique file name
    }
  })
  
  export const upload = multer({ 
    storage,
})



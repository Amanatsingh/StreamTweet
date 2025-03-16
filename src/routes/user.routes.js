import { Router } from "express";
import { registerUser } from "../controllers/user.controller.js";
import {upload} from "../middlewares/multer.middleware.js";

const router = Router();


//router.route("/register").post(registerUser)
router.route("/register").post(
    upload.fields([
        { 
            name: "avatar", 
            maxCount: 1 
        },
        { 
            name: "coverImage",
            maxCount: 1 
        }
    ]),
    registerUser                         //isse just pehle multer middleware chalega
)

export default router;             //default - koi v naam de sakte hain while importing this 
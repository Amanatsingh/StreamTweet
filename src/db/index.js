import mongoose from "mongoose";
import { DB_NAME } from "../constant.js";

const connectDB = async () => {
  try {
    const connectionInstance = await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`);
    console.log(`\n MongoDB connected !! DB HOST: ${connectionInstance.connection.host}`);   //mongoDB ka jo URL hai jha connection ho rha hai wo lele
  } catch (error) {
    console.error("MongoDB connection FAILED", error);
    process.exit(1);
  }
}

export default connectDB;  
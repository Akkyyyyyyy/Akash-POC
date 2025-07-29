import mongoose from "mongoose";
import { config } from "dotenv";

config();

export const dbConnection = async() => {
    try {
        const conn = await mongoose.connect(process.env.MONGO_URI);
        console.log(`MongoDB Connected`);
      } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
      }
};
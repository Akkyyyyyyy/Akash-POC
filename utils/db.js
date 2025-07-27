import mongoose from "mongoose";
import { config } from "dotenv";

config();

export const dbConnection = async() => {
    try {
        const conn = await mongoose.connect('mongodb+srv://agavde404:CK70CH9FwsKy7ETC@cluster0.en4w7.mongodb.net/new?retryWrites=true&w=majority&appName=Cluster0');
        console.log(`MongoDB Connected`);
      } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
      }
};
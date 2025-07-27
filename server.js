import express from 'express';
import cors from 'cors';
import { dbConnection } from './utils/db.js';
import dotenv from 'dotenv';
import { userRoute } from './routes/user.route.js';

dotenv.config();
console.log("Loaded SECRET_KEY:", process.env.SECRET_KEY); // 🔍 Add this



const app = express();

dbConnection(); 

app.use(cors());
app.use(express.json());

app.use('/user',userRoute)
const PORT = process.env.PORT || 5000;
const HOST = '0.0.0.0'; // Listen on all network interfaces

app.listen(PORT, HOST, () => {
    console.log(`Server running on http://${HOST}:${PORT}`);
    console.log(`Local access: http://localhost:${PORT}`);
    console.log(`Network access: http://192.168.12.4:${PORT}`);
});

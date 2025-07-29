import express from 'express';
import cors from 'cors';
import { dbConnection } from './utils/db.js';
import dotenv from 'dotenv';
import { userRoute } from './routes/user.route.js';

dotenv.config();


const app = express();


dbConnection(); 

app.use(cors());
app.use(cors({ origin: '*' }));
app.use(express.json());

app.use('/user',userRoute)
const PORT = process.env.PORT || 8000;
const HOST = '0.0.0.0'; 

app.listen(PORT, HOST, () => {
    console.log(`Local access: http://localhost:${PORT}`);
});

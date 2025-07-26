import express from 'express';
import cors from 'cors';
import { dbConnection } from './utils/db.js';
import { configDotenv } from 'dotenv';
import { userRoute } from './routes/user.route.js';

configDotenv(); 

const app = express();

dbConnection(); 

app.use(cors());
app.use(express.json());

app.use('/user',userRoute)
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

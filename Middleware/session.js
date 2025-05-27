import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

export const checkAuth = async (req,res,next)=>{
    const authHeader = req.headers['authorization'];
    const token = authHeader?.split(' ')[1];
    if(!token){
        return res.status(401).json({message:"Unauthorized"});
    }
    try{
        const decoded = jwt.verify(token,process.env.JWT_SECRET);
        req.user = decoded;
        next();
    }catch(err){
        res.status(401).json({message:"Unauthorized"});
    }
}
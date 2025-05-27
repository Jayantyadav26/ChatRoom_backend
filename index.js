import express from 'express';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import {hash,compare} from './scrypt.js';
import {checkAuth} from './Middleware/session.js';  

const app = express();
app.use(cors());
app.use(express.json());

dotenv.config();
const port = process.env.PORT;

const db = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 3306,
})

try{
    await db.connect();
    console.log('Connected to database');
}catch(err){
    console.log("Database connection error: ",err);
}


app.post("/signup" , async(req,res) =>{
    const {username,password} = req.body;

    try{
        const [result] = await db.query('SELECT * FROM users WHERE username = ?',[username]);
        if(result.length > 0){
            return res.status(400).json({message:"Username already exists"});
        }
            const hashedPassword = await hash(password,10);
            await db.query('INSERT INTO users (username,password_hash) VALUES (?,?)',[username,hashedPassword]);
            res.status(200).json({message:"User created successfully"});
        
    }catch(err){
        console.log(err);
        res.status(500).json({message:"Internal server error"});
    }
})

app.post('/login', async(req,res)=>{
    const {username,password} = req.body;
    try{
        const [result] = await db.query('SELECT * FROM users WHERE username=?' ,[username]);
        if(result.length === 0){
            return res.status(400).json({message:"Username not found"});
        }

            const user = result[0];
            const hashedPassword  = await compare(password,user.password_hash);
            if(!hashedPassword){
                return res.status(400).json({message:"Incorrect password"});
            }

            const token = jwt.sign({username: user.username, userId: user.id}, process.env.JWT_SECRET, {expiresIn: '1h'});
            res.status(200).json({message:"Login successful",token});
    }catch(err){
        console.log(err);
        res.status(500).json({message:"Internal server error"});
    }
})

app.get('/dashboard', checkAuth, async (req, res) => {
  const userId = req.user.userId;

  try {
    const [userSpaces] = await db.query(
      'SELECT space_id FROM user_spaces WHERE user_id = ?', 
      [userId]
    );

    if (userSpaces.length === 0) {
      return res.status(200).json({ message: "No spaces joined yet", spaces: [] });
    }

    const spaceIds = userSpaces.map(row => row.space_id);

    // Ensure SQL handles multiple IDs properly
    const [spaces] = await db.query(
      `SELECT * FROM spaces WHERE id IN (${spaceIds.map(() => '?').join(',')})`,
      spaceIds
    );

    return res.status(200).json({ spaces });

  } catch (err) {
    console.error("Dashboard error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});


app.post('/create-room',checkAuth,async(req,res)=>{
    const {spaceName,spacePassword,description} = req.body;
    const ownerId = req.user.userId;
    //get owner id from token
    try{
        console.log(spaceName);
        const [result] = await db.query('SELECT * FROM spaces WHERE name=?' ,[spaceName]);
        if(result.length > 0){
            return res.status(400).json({message:"Space already exists"});
        }
        const hashedPassword = await hash(spacePassword,10);
        await db.query('INSERT INTO spaces (name,owner_id,spacePass,description) VALUES (?,?,?,?)',[spaceName,ownerId,hashedPassword,description]);
        res.status(200).json({message:"Space created successfully"});
    }catch(err){
        console.log(err);
        res.status(500).json({message:"Internal server error"});
    }
})

app.post('/join-room',checkAuth,async(req,res)=>{
    const {spaceName,spacePassword} = req.body;
    const userId = req.user.userId;
    try{
        //check for space existence
        const [result] = await db.query('SELECT * FROM spaces WHERE name=?' ,[spaceName]);
        if(result.length === 0){
            return res.status(400).json({message:"Space not found"});
        }
        const check = await compare(spacePassword,result[0].spacePass);
        if(!check){
            return res.status(400).json({message:"Incorrect password"});
        }
        const [existing] = await db.query('SELECT * FROM user_spaces WHERE user_id=? AND space_id=?', [userId, result[0].id]);
        if (existing.length > 0) {
            return res.status(400).json({ message: "Already joined this room" });
        }
        await db.query('INSERT IGNORE INTO user_spaces (user_id,space_id) VALUES (?,?)',[userId,result[0].id]);
        res.status(200).json({message:"Room joined successfully"});
    }catch(err){
        console.log(err);
        res.status(500).json({message:"Internal server error"});
    }
})

//search space using name
app.get('/search-room', checkAuth, async (req, res) => {
    const { spaceName } = req.query;

    try {
        const [result] = await db.query(
            'SELECT * FROM spaces WHERE name LIKE ?',
            [`%${spaceName}%`]
        );

        if (result.length === 0) {
            return res.status(404).json({ message: "Space not found" });
        }

        // ✅ Wrap the result in a 'rooms' key to match frontend expectations
        res.status(200).json({ rooms: result });
    } catch (err) {
        console.error("Error in /search-room:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

//check space existence
app.get('/check-space', checkAuth, async (req, res) => {
    const { spaceName } = req.query;

    if (!spaceName) {
        return res.status(400).json({ message: "Missing spaceName parameter" });
    }

    try {
        const [result] = await db.query(
            'SELECT * FROM spaces WHERE name LIKE ?',
            [`%${spaceName}%`]
        );

        if (result.length === 0) {
            return res.status(200).json({ message: "Space not found" });
        } else {
            return res.status(403).json({ message: "Space already exists" });
        }
    } catch (err) {
        console.error("Database error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});


// app.delete("/exitRoom",checkAuth, (req,res)=>{
//     const {userId,spaceId} = req.body;

//     if(!userId || !spaceId){
//         return res.status(400).json({message: "Missing userId and spaceId "});
//     }

//     try{
        
//     }catch(err){

//     }

// })  


app.listen(port, ()=>{
    console.log(`Server is running on port ${port}`);
})


// //adding a friend 
// app.post('/addfriend', checkAuth,async(req,res)=>{
//     const {friendUsername,userId} = req.body;
//     //get user_id from token

//     try{
//         //check for user existence
//         const [result] = await db.query('SELECT * FROM users WHERE id=?' ,[friendUsername]);
//         if(result.length === 0){
//             return res.status(400).json({message:"User not found"});
//         }

//         if(result[0].id === userId){
//             return res.status(400).json({message:"You can't add yourself as a friend"});
//         }  

//         await db.query('INSERT INTO friends (user_id,friend_id) VALUES (?,?)',[userId,result[0].id]);
//         await db.query('INSERT INTO friends (user_id,friend_id) VALUES (?,?)',[result[0].id,userId]);
//         res.status(200).json({message:"Friend added successfully"});
//     }catch(err){
//         console.log(err);
//         res.status(500).json({message:"Internal server error"});
//     }
// })
// //show all available users and search user with a name
// app.get('/findfriends',checkAuth,async(req,res)=>{
//     const {friendUsername} = req.body;
//     //get user_id from token        
//     try{
//         const [result] = await db.query('SELECT * FROM users WHERE username like ?' ,[`%${friendUsername}%`]);
//         if(result.length === 0){
//             return res.status(400).json({message:"User not found"});
//         }
//         res.status(200).json(result);
//     }catch(err){
//         console.log(err);
//         res.status(500).json({message:"Internal server error"});
//     }
// })

// app.get('/get-friends',checkAuth,async(req,res)=>{
//     const {userId} = req.body;
//     //get user_id from token

//     try{
//         const [result] = await db.query('SELECT * FROM friends WHERE user_id=?' ,[userId]);
//         if(result.length === 0){
//             return res.status(400).json({message:"User not found"});
//         }
//         res.status(200).json(result);
//     }catch(err){
//         console.log(err);
//         res.status(500).json({message:"Internal server error"});
//     }
// })


// //basically stores a message in db.
// app.post('/send-message',checkAuth,async(req,res)=>{
//     const {userId,message,spaceId} = req.body;
//     //get user_id from token

//     try{
//         const [result] = await db.query('SELECT * FROM user_spaces WHERE user_id=? && space_id=?' ,[userId,spaceId]);
//         if(result.length === 0){
//             return res.status(400).json({message:"User not found"});
//         }
//         await db.query('INSERT INTO messages (user_id,message,space_id) VALUES (?,?,?)',[userId,message,result[0].space_id]);
//         res.status(200).json({message:"Message sent successfully"});
//     }catch(err){
//         console.log(err);
//         res.status(500).json({message:"Internal server error"});
//     }
// })



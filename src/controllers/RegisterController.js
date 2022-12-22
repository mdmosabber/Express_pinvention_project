const asyncHandler = require('express-async-handler');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { rawListeners } = require('../models/user');
const User = require('../models/user');
const Token = require('../models/token');
const crypto = require('crypto');
const sendEmail = require('../utils/sendEmail');
const { stat } = require('fs');


//Generate Token
const generateToken = (id)=>{
    return jwt.sign({id}, process.env.JWT_SECRET, {expiresIn: '7d'});
}

// Set Cookie
const setCookieMethod = (res, token)=> {
    res.cookie("token", token,{
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 7 * 1000 * 86400),
        sameSite: "none" 
    });
}

exports.index = (req, res)=> {
    const token = req.cookies.token;
    res.send('Allah Mohan Allah Mohan '+ token);    
}


// Register user
exports.registerUser = asyncHandler(async(req, res)=> {
    const { name, email, password} = req.body;

    if(!name || !email || !password){
        res.status(400);
        throw new Error("Please fill in all required fields");
    };

    if(password.length < 6){
        res.status(400);
        throw new Error("Password must be up to 6 characters");
    };

    const userExists = await User.findOne({email});
    if(userExists){
        res.status(400);
        throw new Error("Email has already been used");
    };

    const user = await User.create({
        name, email, password
    });

    const token = generateToken(user._id);

    setCookieMethod(res, token);

    if(user){
        const { _id, name, email, image, phone, description } = user;
        res.status(201).json({
            _id, name, email, image, phone, description, token
        })
    }else{
        res.status(400);
        throw new Error('Invalid user date');
    }
}) 



//Login User
exports.loginUser = asyncHandler( async(req, res)=> {
    const { email, password} = req.body;
   
    if(!email || !password){
        res.status(400);
        throw new Error("Please add email and password");
    }

    const user = await User.findOne({email});

    if(!user){
        res.status(400);
        throw new Error('User not found, please signup');
    }

    const passwordIsCorect = await bcrypt.compare(password, user.password);

    const token = generateToken(user._id);

    setCookieMethod(res, token);

    if(user && passwordIsCorect){
        const { _id, name, email, image, phone, description } = user;
        res.status(201).json({
            _id, name, email, image, phone, description, token
        })
    }else{
        res.status(400);
        throw new Error('Invalid email or password');
    }
  
}) 



//Logout
exports.logout = asyncHandler( async(req, res)=> {
    setCookieMethod(res, "");
    return res.status(200).json({mesage: "Logged Out Successfully"});
})



// get user
exports.getUser = asyncHandler( async(req, res)=> {
    const user = await User.findById(req.user._id);
    if(user){
        const { _id, name, email, image, phone, description } = user;
        res.status(201).json({
            _id, name, email, image, phone, description
        })
    }else{
        res.status(400);
        throw new Error('User Not Found');
    }
   
})



// Logged in user
exports.loginStatus = asyncHandler(async(req, res)=> {
    const token = req.cookies.token;

    if(!token){
        return res.json(false);
    }

    const verified = jwt.verify(token, process.env.JWT_SECRET);

    if(verified){
        return res.json(true)
    }else{
        return res.json(false) 
    }
})



//Update user
exports.updateUser = asyncHandler( async(req, res)=> {   
    const user = await User.findById(req.user._id);

    if(user){
        const { name, email, image, phone, description  } = user;
        user.email = email;
        user.name  = req.body.name || name;
        user.image = req.body.image || image;
        user.phone = req.body.phone || phone;
        user.description = req.body.description || description;

        const updatedUser = await user.save();

        res.status(200).json(updatedUser)
    }else{
        res.status(400);
        throw new Error('User Not Found');
    }
})




// Change Password
exports.changePassword = asyncHandler(async(req, res)=> {
    const user = await User.findById(req.user._id);
    const {oldPassword, newPassword} = req.body;

    if(!user){
        res.status(400);
        throw new Error('User not found, please signup');
    }

    if(!oldPassword || !newPassword ){
        res.status(400);
        throw new Error('Please add old and new password');
    }

    const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

    if(user && passwordIsCorrect){
        user.password = newPassword;
        await user.save();
        res.status(200).send('Password change successfully');        
    }else{
        res.status(400);
        throw new Error("Old password is incorrect")
    }
   
})



// Forgot Password
exports.forgotPassword = asyncHandler( async(req, res)=> {
   const {email} = req.body;

   const user = await User.findOne({ email });

  if(!user){
    res.status(404);
    throw new Error("User does not exist");
  }

  // Delete token if it exists in DB
  let token = await Token.findOne({userId: user._id});
  if(token){
    await token.deleteOne();
  }

  // Create Reset Token
  let resetToken = crypto.randomBytes(32).toString('hex') + user._id;
  console.log("Reset Token: ",resetToken);

  //Create Hash token before saving to DB
  const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");
  console.log("Hashed Token: ",hashedToken);

  //Save Token in DB
  await new Token({
    userId: user._id,
    token: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 30 * (60 * 1000), // 30 minutes
  }).save();


  // Reset URL
  const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

  // Reset Email
  const message = `
    <h2> ${user.name} </h2>
    <p> Please use the url below to reset your password </p>
    <p> This reset link is valid for only 30 minutes </p>
    <a href="${resetUrl}" clicktracking=off> ${resetUrl} </a>
    <p>Regards...</p>
    <p>Pinvent Team</p>
  `;

  const subject = 'Password Reset Request';
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;

  try{
    await sendEmail(subject, message, send_to, sent_from);
    res.status(200).json({success: true, message: "Reset Email Sent, Check Your Email"});
  }catch(error){
    res.status(500);
    throw new Error("Email not sent, please try again");
  }


})
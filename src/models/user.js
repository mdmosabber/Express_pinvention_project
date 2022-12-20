const mongoose = require("mongoose");
const bcrypt = require('bcryptjs');
const { Schema } = mongoose;

const userSchema = new Schema(
    {
        name:{
            type: String,
            required: [true, "Name is requie"]
        },
        email: {
            type: String,
            required: [true, "Email is require"],
            unique: true,
            trim: true,
            match: [
                /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
                "Please enter a valid email"
              ]
        },
        password: {
            type: String,
            required: [true, "Please add a password"],
            minLength: [6, "Password must be up to 6 characters"],
            // maxLength: [23, "Password must not be more than 23 characters"],
        },
        image: {
            type: String,
            required: [true, 'Please add a photo'],
            default: "https://i.ibb.co/4pDNDk1/avatar.png",
        },
        phone: {
            type: String,
            default: "+8801722334455",
        },
        description: {
            type: String,
            maxLength: [250, "Bio must not be more than 250 characters"],
            default: "I am MR. Jhon ...",
        },
    },
    {timestamps: true, versionKey: false}
)


userSchema.pre('save',async function(next){
    if(!this.isModified('password')){
        return next();
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(this.password, salt);
    this.password = hashedPassword;
    next()
})

const User = mongoose.model('User', userSchema);

module.exports = User;
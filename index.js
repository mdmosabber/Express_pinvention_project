const mongoose = require("mongoose");
const app = require('./src/app');
const port = process.env.port || 8080;
const database = process.env.DATABASE;

mongoose.set('strictQuery', false);


mongoose.connect(database)
.then(()=> {
    app.listen(port, ()=> {
        console.log(`Server Run Succesfully at http://localhost:${port}`);
    })
})
.catch((error)=> {
    console.log(error)
})

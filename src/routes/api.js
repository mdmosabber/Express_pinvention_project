const { index, registerUser, loginUser, logout, getUser, loginStatus, updateUser, changePassword} = require('../controllers/RegisterController');
const protect = require('../middleware/auth');

const router = require('express').Router();


router.get('/',index);
router.post('/register', registerUser);
router.post('/login', loginUser);
router.get('/logout', logout);
router.get('/getuser',protect,getUser);
router.get('/loggedin', loginStatus);
router.patch('/updateuser',protect,updateUser);
router.patch('/change-password',protect, changePassword)




module.exports = router;
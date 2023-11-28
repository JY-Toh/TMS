const express = require("express")
const router = express.Router()

// const { loginUser, logout, registerUser } = require("../controllers/authController")
// const { isAuthenticatedUser, authorizeRoles } = require("../middleware/auth")
const { isAuthenticatedUser, authorizeRoles } = require("../middleware/auth")
const { userProfile, viewUsers, updateProfile, addGroup } = require("../controllers/userController")

router.route("/viewUsers").get(isAuthenticatedUser, authorizeRoles("admin"), viewUsers)
router.route("/profile").get(isAuthenticatedUser, userProfile)
router.route("/profile/update").put(isAuthenticatedUser, updateProfile)
router.route("/addGroup").post(isAuthenticatedUser, authorizeRoles("admin"), addGroup)

module.exports = router

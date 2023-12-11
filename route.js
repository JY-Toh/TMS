const express = require("express")
const router = express.Router()

const { loginUser, logout, registerUser, userProfile, viewUsers, updateProfile, addGroup, statusChange, updateUser, viewGroups } = require("./controller")
const { isAuthenticatedUser, authorizeRoles, checkingGroup } = require("./auth")
const {getApps} = require("./controller")

//Routes for all users
router.route("/login").post(loginUser)
router.route("/_logout").get(isAuthenticatedUser, logout)
router.route("/checkgroup").post(isAuthenticatedUser, checkingGroup)

router.route("/profile").get(isAuthenticatedUser, userProfile)
router.route("/profile/update").post(isAuthenticatedUser, updateProfile)

//Routes for A2
router.route("/getApps").get(isAuthenticatedUser,getApps)


//Routes for users with admin rights
router.route("/viewUsers").get(isAuthenticatedUser, authorizeRoles("admin"), viewUsers)
router.route("/register").post(isAuthenticatedUser, authorizeRoles("admin"), registerUser)
router.route("/addGroup").post(isAuthenticatedUser, authorizeRoles("admin"), addGroup)
router.route("/updateUser").post(isAuthenticatedUser, authorizeRoles("admin"), updateUser)
router.route("/statusChange").post(isAuthenticatedUser, authorizeRoles("admin"), statusChange)
router.route("/viewGroups").get(isAuthenticatedUser, authorizeRoles("admin"), viewGroups)

module.exports = router

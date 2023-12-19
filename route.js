const express = require("express")
const router = express.Router()

const { loginUser, logout, registerUser, userProfile, viewUsers, updateProfile, addGroup, statusChange, updateUser, viewGroups } = require("./controller")
const { isAuthenticatedUser, authorizeRoles, checkingGroup } = require("./auth")
const { getApps, createApp, updateApp, getAppInfo, getTasks, getTasksApp, createTask, getTaskInfo, updateNotes, promoteTask, rejectTask, returnTask, getPlan, getPlanApp, createPlan, updatePlan, assignTaskPlan } = require("./controller")

//Routes for all users
router.route("/login").post(loginUser)
router.route("/_logout").get(isAuthenticatedUser, logout)
router.route("/checkgroup").post(isAuthenticatedUser, checkingGroup)

router.route("/profile").get(isAuthenticatedUser, userProfile)
router.route("/profile/update").post(isAuthenticatedUser, updateProfile)

//Routes for A2
router.route("/getApps").get(isAuthenticatedUser, getApps)
router.route("/createApp").post(isAuthenticatedUser, createApp)
router.route("/updateApp/:App_Acronym").post(isAuthenticatedUser, updateApp)
router.route("/getAppInfo/:App_Acronym").get(isAuthenticatedUser, getAppInfo)
router.route("/getTasksApp/:App_Acronym").get(isAuthenticatedUser, getTasksApp)
router.route("/createTask").post(isAuthenticatedUser, createTask)
router.route("/getTaskInfo/:Task_id").get(isAuthenticatedUser, getTaskInfo)
router.route("/updateNotes/:Task_id").post(isAuthenticatedUser, updateNotes)
router.route("/promoteTask/:Task_id").post(isAuthenticatedUser, promoteTask)
router.route("/rejectTask/:Task_id").post(isAuthenticatedUser, rejectTask)
router.route("/returnTask/:Task_id").post(isAuthenticatedUser, returnTask)
router.route("/getPlan").get(isAuthenticatedUser, getPlan)
router.route("/getPlanApp/:App_Acronym").get(isAuthenticatedUser, getPlanApp)
router.route("/createPlan").post(isAuthenticatedUser, createPlan)
router.route("/updatePlan").post(isAuthenticatedUser, updatePlan)
router.route("/assignTaskPlan/:Task_id").post(isAuthenticatedUser, assignTaskPlan)

//Routes for users with admin rights
router.route("/viewUsers").get(isAuthenticatedUser, authorizeRoles("admin"), viewUsers)
router.route("/register").post(isAuthenticatedUser, authorizeRoles("admin"), registerUser)
router.route("/addGroup").post(isAuthenticatedUser, authorizeRoles("admin"), addGroup)
router.route("/updateUser").post(isAuthenticatedUser, authorizeRoles("admin"), updateUser)
router.route("/statusChange").post(isAuthenticatedUser, authorizeRoles("admin"), statusChange)
router.route("/viewGroups").get(isAuthenticatedUser, viewGroups)

module.exports = router

import {Router} from "express"
import AuthController from "../controllers/Auth"

const userRouter = Router()

userRouter.post("/register", AuthController.register)
userRouter.post("/login", AuthController.login)

export default userRouter
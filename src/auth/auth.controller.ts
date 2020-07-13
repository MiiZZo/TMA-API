import {
  Post,
  Controller,
  Body,
  UsePipes,
  UseGuards,
  Req,
  Res
} from "@nestjs/common";
import { User } from "./user.interface";
import { JoiValidationPipe } from "../joi-validation.pipe";
import { userValidationSchema } from "./validation.schemas";
import { LocalAuthGuard } from "./guards/local-auth.guard";
import { AuthService } from "./auth.service";
import { Request, Response } from "express";

@Controller("auth")
export class AuthController {
  constructor(private authService: AuthService) {}

  @UsePipes(new JoiValidationPipe(userValidationSchema))
  @Post("register")
  async register(@Body() user: User) {
    this.authService.createUser(user);
  }

  @UseGuards(LocalAuthGuard)
  @Post("login")
  async login(@Req() req: Request, @Res() res: Response) {
    const tokens = await this.authService.login(req.user);
    res.cookie("access_token", tokens.access_token, {
      httpOnly: true,
      maxAge: 1800 * 1000 // 30 min
    });
    res.cookie("refresh_token", tokens.refresh_token, {
      httpOnly: true,
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    });
    res.end();
  }
}

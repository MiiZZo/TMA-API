import { Injectable, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { UsersService } from "../users/users.service";
import { User } from "./user.interface";
import bcrypt from "bcryptjs";
import { InjectModel } from "@nestjs/mongoose";
import { RefreshToken } from "./auth.schema";
import { Model } from "mongoose";

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    @InjectModel(RefreshToken.name)
    private refreshTokenModel: Model<RefreshToken>
  ) {}

  async createUser(user: User) {
    const userRegistered = this.usersService.findOne(user.email);
    if (userRegistered === null) {
      throw new UnauthorizedException(
        "User with this email already registered"
      );
    }
    const hashPassword = bcrypt.hashSync(user.password);
    this.usersService.createUser({
      email: user.email,
      password: hashPassword
    });
  }

  async validateUser(
    email: string,
    password: string
  ): Promise<{ id: string } | null> {
    const user = await this.usersService.findOne(email);
    if (user !== null) {
      const matchedPassword = this.comparePassword(password, user.password);
      if (matchedPassword) {
        const { id } = user;
        return { id };
      }
    }
    return null;
  }

  async login(user: any) {
    const payload = { sub: user.id };
    const access_token = this.jwtService.sign(payload, {
      expiresIn: "30min"
    });
    const refresh_token = this.jwtService.sign(payload, {
      expiresIn: "30days"
    });
    (await this.refreshTokenModel.create({ refresh_token })).save();
    return {
      access_token,
      refresh_token
    };
  }

  hashPassword(password: string) {
    return bcrypt.hashSync(password);
  }

  comparePassword(password: string, hash: string) {
    return bcrypt.compareSync(password, hash);
  }
}

import { Injectable } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { User as UserModel, User } from "./users.schema";

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(UserModel.name) private userModel: Model<UserModel>
  ) {}

  async createUser(user: { password: string; email: string }) {
    const newUser = await this.userModel.create(user);
    await newUser.save();
  }

  async findOne(email: string): Promise<User | null> {
    return await this.userModel.findOne({ email });
  }
}

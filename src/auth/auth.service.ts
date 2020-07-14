import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { User } from './user.interface';
import * as bcrypt from 'bcryptjs';
import { InjectModel } from '@nestjs/mongoose';
import { RefreshToken } from './auth.schema';
import { Model } from 'mongoose';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    @InjectModel(RefreshToken.name)
    private refreshTokenModel: Model<RefreshToken>,
  ) {}

  async createUser(user: User): Promise<void> {
    const userRegistered = await this.usersService.findOne(user.email);
    if (userRegistered !== null) {
      throw new UnauthorizedException(
        'Пользователь с данным e-mail уже зарегистрирован.',
      );
    }
    const hashPassword = bcrypt.hashSync(user.password);
    await this.usersService.createUser({
      email: user.email,
      password: hashPassword,
    });
  }

  async validateUser(
    email: string,
    password: string,
  ): Promise<{ id: string } | null> {
    const user = await this.usersService.findOne(email);
    if (user !== null) {
      const matchedPassword = bcrypt.compareSync(password, user.password);
      if (matchedPassword) {
        const { id } = user;
        return { id };
      }
    }
    return null;
  }

  async login(user: {
    id: string;
  }): Promise<{
    access_token: string;
    refresh_token: string;
  }> {
    const payload = { sub: user.id };
    const access_token = this.jwtService.sign(payload, {
      expiresIn: '30min',
    });
    const refresh_token = this.jwtService.sign(payload, {
      expiresIn: '30days',
    });
    (await this.refreshTokenModel.create({ refresh_token })).save();
    return {
      access_token,
      refresh_token,
    };
  }
}

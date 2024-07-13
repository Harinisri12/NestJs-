import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { RegisterUserDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { DatabaseService } from 'src/database/database.service'; // Adjusted path to DatabaseService
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {

  constructor(
    private readonly databaseService: DatabaseService, // Adjusted variable name to camelCase
    private readonly jwtService: JwtService // Adjusted variable name to camelCase
  ) {}

  async login(loginData: LoginDto) {
    const { email, password } = loginData;
    const user = await this.databaseService.user.findFirst({
      where: {
        email: email
      }
    });

    if (!user) {
      throw new NotFoundException('No user exists with the entered email');
    }

    const validatePassword = await bcrypt.compare(password, user.password);
    if (!validatePassword) {
      throw new NotFoundException('Wrong Password');
    }

    return {
      token: this.jwtService.sign({ email })
    };
  }

  async register(registerData: RegisterUserDto) {
    const existingUser = await this.databaseService.user.findFirst({
      where: {
        email: registerData.email
      }
    });

    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    registerData.password = await bcrypt.hash(registerData.password, 10);
    const res = await this.databaseService.user.create({ data: registerData }); // Adjusted variable name to camelCase
    return res;
  }
}

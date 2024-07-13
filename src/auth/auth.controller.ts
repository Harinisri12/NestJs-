import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterUserDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ApiOperation, ApiTags } from '@nestjs/swagger';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  @ApiOperation({ summary: 'Register a new user with email.' })
  create(@Body() registerData: RegisterUserDto) {
    return this.authService.register(registerData);
  }

  @Post('login') // Changed from @Get('login') to @Post('login')
  @ApiOperation({ summary: 'Login with email.' })
  login(@Body() loginData: LoginDto) {
    return this.authService.login(loginData);
  }
}

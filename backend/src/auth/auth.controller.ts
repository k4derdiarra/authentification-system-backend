import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('local/signup')
  signupLocal(@Body() dto: AuthDto): Promise<{ access_token: string }> {
    return this.authService.signupLocal(dto);
  }

  @Post('local/signin')
  signinLocal(@Body() dto: AuthDto): Promise<{ access_token: string }> {
    return this.authService.signinLocal(dto);
  }
}

import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { GetUser } from './decorator';
import {
  GoogleAuthDto,
  JwtAccessAndRefreshTokenDto,
  LocalSignupAuthDto,
} from './dto';
import { LocalSigninAuthDto } from './dto';
import { GoogleAuthGuard } from './guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('local/signup')
  signupLocal(@Body() dto: LocalSignupAuthDto): JwtAccessAndRefreshTokenDto {
    return this.authService.signupLocal(dto);
  }

  @Post('local/signin')
  signinLocal(@Body() dto: LocalSigninAuthDto): JwtAccessAndRefreshTokenDto {
    return this.authService.signinLocal(dto);
  }

  @Get('google')
  @UseGuards(GoogleAuthGuard)
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  googleAuth() {}

  @Get('google/redirect')
  @UseGuards(GoogleAuthGuard)
  googleAuthRedirect(
    @GetUser() dto: GoogleAuthDto,
  ): JwtAccessAndRefreshTokenDto {
    return this.authService.signinGoogle(dto);
  }
}

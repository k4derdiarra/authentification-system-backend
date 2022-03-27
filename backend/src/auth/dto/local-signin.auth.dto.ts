import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class LocalSigninAuthDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}

import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { UsersService } from 'src/modules/users/users.service';
import { LoginDto } from '../dto/login.dto';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { Public } from 'src/modules/auth/decorator/public.decorator';
import { JwtService } from '@nestjs/jwt';
import { User } from 'src/modules/users/entities/user.entity';
import { ExcludeFromObject } from 'src/common/dto/sanitize-response.dto';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, pass: string): Promise<User> {
    const user = await this.usersService.findByEmail(email);
    if (!user || !(await user.comparePassword(pass))) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return ExcludeFromObject(user,["password"]);
  }

  async forgotPassword(dto: ForgotPasswordDto) {
    const user = await this.usersService.findByEmail(dto.email);
    if (!user) {
      throw new BadRequestException('User not found');
    }

    const resetToken = this.jwtService.sign(
      { userId: user.id },
      {
        secret: process.env.JWT_RESET_SECRET || 'reset-secret',
        expiresIn: '1h',
      },
    );
    return {
      message: 'Password reset instructions sent to your email',
      resetToken,
    };
  }

  async resetPassword(token: string, password: string) {
    try {
      const decoded = this.jwtService.verify(token, {
        secret: process.env.JWT_RESET_SECRET || 'reset-secret',
      });

      const user = await this.usersService.findById(decoded.userId);
      if (!user) {
        throw new BadRequestException('Invalid token');
      }

      await this.usersService.updatePassword(decoded.userId, password);
      return { message: 'Password successfully reset' };
    } catch {
      throw new BadRequestException('Invalid or expired token');
    }
  }

  async changePassword(userId: number, dto: ChangePasswordDto) {
    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (!(await user.comparePassword(dto.currentPassword))) {
      throw new BadRequestException('Current password is incorrect');
    }

    if (dto.newPassword !== dto.confirmPassword) {
      throw new BadRequestException('New passwords do not match');
    }

    await this.usersService.updatePassword(userId, dto.newPassword);
    return { message: 'Password successfully changed' };
  }

  @Public()
  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;
    const user = await this.validateUser(email, password);

    const payload = { email: user.email, sub: user.id };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}

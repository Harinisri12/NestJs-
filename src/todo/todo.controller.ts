import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards } from '@nestjs/common';
import { TodoService } from './todo.service';
import { CreateTodoDto } from './dto/create-todo.dto';
import { UpdateTodoDto } from './dto/update-todo.dto';
import { JwtAuthGuard } from '../auth/auth.guard';
import { UserEmail } from '../common/decorator/user-email.decorator';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';

@ApiTags('Todo')
@Controller('todo')
export class TodoController {
  constructor(private readonly todoService: TodoService) {}

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post()
  @ApiOperation({
    summary: 'Create a new todo item',
    description: 'This endpoint allows an authenticated user to create a new todo item. The user must provide the necessary details such as title and description in the request body.'
  })
  create(@Body() createTodoDto: CreateTodoDto, @UserEmail() userEmail: string) {
    return this.todoService.create(createTodoDto, userEmail);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get()
  @ApiOperation({
    summary: 'Get all todo items',
    description: 'This endpoint retrieves all todo items for the authenticated user. The user\'s email is used to fetch their specific todo items.'
  })
  findAll(@UserEmail() userEmail: string) {
    return this.todoService.findAll(userEmail);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get(':id')
  @ApiOperation({
    summary: 'Get a specific todo item',
    description: 'This endpoint retrieves a specific todo item by its ID. The ID should be provided as a path parameter.'
  })
  findOne(@Param('id') id: string) {
    return this.todoService.findOne(+id);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Patch(':id')
  @ApiOperation({
    summary: 'Update a specific todo item',
    description: 'This endpoint allows an authenticated user to update a specific todo item by its ID. The ID should be provided as a path parameter, and the updated details should be provided in the request body.'
  })
  update(@Param('id') id: string, @Body() updateTodoDto: UpdateTodoDto) {
    return this.todoService.update(+id, updateTodoDto);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Delete(':id')
  @ApiOperation({
    summary: 'Delete a specific todo item',
    description: 'This endpoint allows an authenticated user to delete a specific todo item by its ID. The ID should be provided as a path parameter.'
  })
  remove(@Param('id') id: string) {
    return this.todoService.remove(+id);
  }
}
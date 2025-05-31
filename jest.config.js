module.exports = {
    testEnvironment: 'jsdom',  // 使用jsdom环境模拟浏览器
    setupFilesAfterEnv: ['./jest.setup.js'],  // 可选的设置文件
    moduleNameMapper: {
      '\\.(css|less|scss)$': '<rootDir>/__mocks__/styleMock.js'  // 处理样式文件
    }
  };